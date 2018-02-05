#include "error.h"
#include "ipmgr.h"
#include "timespec.h"
#include "if.h"
#include "intercom.h"
#include "l3roamd.h"
#include "util.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_tun.h>

static bool tun_open(ipmgr_ctx *ctx, const char *ifname, uint16_t mtu, const char *dev_name);
static void schedule_ipcheck(ipmgr_ctx *ctx, struct entry *e);
static void ipcheck_task(void *d);
static void seek_task(void *d);
static bool ipcheck(ipmgr_ctx *ctx, struct entry *e);

/* open l3roamd's tun device that is used to obtain packets for unknown clients */
bool tun_open(ipmgr_ctx *ctx, const char *ifname, uint16_t mtu, const char *dev_name) {
	int ctl_sock = -1;
	struct ifreq ifr = {};

	ctx->fd = open(dev_name, O_RDWR|O_NONBLOCK);
	if (ctx->fd < 0)
		exit_errno("could not open TUN/TAP device file");

	if (ifname)
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	if (ioctl(ctx->fd, TUNSETIFF, &ifr) < 0) {
		puts("unable to open TUN/TAP interface: TUNSETIFF ioctl failed");
		goto error;
	}

	ctx->ifname = strndup(ifr.ifr_name, IFNAMSIZ-1);

	ctl_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (ctl_sock < 0)
		exit_errno("socket");

	if (ioctl(ctl_sock, SIOCGIFMTU, &ifr) < 0)
		exit_errno("SIOCGIFMTU ioctl failed");

	if (ifr.ifr_mtu != mtu) {
		ifr.ifr_mtu = mtu;
		if (ioctl(ctl_sock, SIOCSIFMTU, &ifr) < 0) {
			puts("unable to set TUN/TAP interface MTU: SIOCSIFMTU ioctl failed");
			goto error;
		}
	}

	ifr.ifr_flags = IFF_UP | IFF_RUNNING| IFF_MULTICAST | IFF_NOARP | IFF_POINTOPOINT;
	if (ioctl(ctl_sock, SIOCSIFFLAGS, &ifr) < 0 ) {
		puts("unable to set TUN/TAP interface UP: SIOCSIFFLAGS ioctl failed");
		goto error;
	}

	if (close(ctl_sock))
		puts("close");

	return true;

error:
	if (ctl_sock >= 0) {
		if (close(ctl_sock))
			puts("close");
	}
	free(ctx->ifname);

	close(ctx->fd);
	ctx->fd = -1;
	return false;
}

/* find an entry in the ipmgr's unknown-clients list*/
struct entry *find_entry(ipmgr_ctx *ctx, const struct in6_addr *k) {
	// TODO: make use of VECTOR_BSEARCH here.
	for (int i = 0; i < VECTOR_LEN(ctx->addrs); i++) {
		struct entry *e = &VECTOR_INDEX(ctx->addrs, i);
		if (l3ctx.debug) {
			printf("looking for ip ");
			print_ip(k, " comparing with ");
			print_ip(&e->address, "\n");
		}
		if (memcmp(k, &(e->address), sizeof(struct in6_addr)) == 0) {
			if (l3ctx.debug)
				printf(" ... match\n");
			return e;
		}
	}

	return NULL;
}

/** This will remove an entry from the ipmgr unknown-clients list */
void delete_entry(ipmgr_ctx *ctx, const struct in6_addr *k) {
	for (int i = 0; i < VECTOR_LEN(ctx->addrs); i++) {
		struct entry *e = &VECTOR_INDEX(ctx->addrs, i);

		if (memcmp(k, &(e->address), sizeof(struct in6_addr)) == 0) {
			VECTOR_DELETE(ctx->addrs, i);
			break;
		}
	}
}

/** This will seek an address by checking locally and if needed querying the network by scheduling a task */
void seek_address(ipmgr_ctx *ctx, struct in6_addr *addr) {
	char str[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, addr, str, sizeof str);

	printf("\x1b[36mLooking for %s\x1b[0m\n", str);

	if (clientmgr_is_ipv4(CTX(clientmgr), addr))
		arp_send_request(CTX(arp), addr);
	else
		icmp6_send_solicitation(CTX(icmp6), addr);

	// schedule an intercom-seek operation that in turn will only be executed if there is no local client known
	struct ip_task *data = calloc(1, sizeof(struct ip_task));

	data->ctx = ctx;
	memcpy(&data->address, addr, sizeof(struct in6_addr));

	if (data->check_task == NULL)
		data->check_task = post_task(CTX(taskqueue), 0, 100, seek_task, free, data);
	else
		free(data);
}

void handle_packet(ipmgr_ctx *ctx, uint8_t packet[], ssize_t packet_len) {
	struct in6_addr dst;
	memcpy(&dst, packet + 24, 16);

	uint8_t a0 = dst.s6_addr[0];

	// Ignore multicast
	if (a0 == 0xff)
		return;

	char str[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &dst, str, sizeof str);
	printf("Got packet to %s\n", str);

	if (!clientmgr_valid_address(CTX(clientmgr), &dst)) {
		fprintf(stderr, "The destination of the packet (%s) is not within the client prefixes. Ignoring packet\n", str);
		return;
	}

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	struct entry *e = find_entry(ctx, &dst);

	bool new_unknown_dst = !e;

	if (new_unknown_dst) {
		struct entry entry = {
			.address = dst,
			.timestamp = now,
		};

		VECTOR_ADD(ctx->addrs, entry);
		e = &VECTOR_INDEX(ctx->addrs, VECTOR_LEN(ctx->addrs) - 1);
	}

	struct packet *p = malloc(sizeof(struct packet));

	p->timestamp = now;
	p->len = packet_len;
	p->data = malloc(packet_len);

	memcpy(p->data, packet, packet_len);

	VECTOR_ADD(e->packets, p);

	struct timespec then = now;
	then.tv_sec -= SEEK_TIMEOUT;

	if (timespec_cmp(e->timestamp, then) <= 0 || new_unknown_dst) {
		seek_address(ctx, &dst);
		e->timestamp = now;
	}

	schedule_ipcheck(ctx, e);
}

void schedule_ipcheck(ipmgr_ctx *ctx, struct entry *e) {
	struct ip_task *data = calloc(1, sizeof(struct ip_task));

	data->ctx = ctx;
	data->address = e->address;

	if (e->check_task == NULL)
		e->check_task = post_task(CTX(taskqueue), IPCHECK_INTERVAL, 0, ipcheck_task, free, data);
	else
		free(data);
}

void seek_task(void *d) {
	struct ip_task *data = d;
	struct entry *e = find_entry(data->ctx, &data->address);

	if (!e) {
		if (l3ctx.debug) {
			printf("INFO: seek task was scheduled but no remaining packets available for host: ");
			print_ip(&data->address, "\n");
		}
		return;
	}
	e->check_task = NULL;

	if (!clientmgr_is_known_address(&l3ctx.clientmgr_ctx, &data->address, NULL)) {
		if (l3ctx.debug) {
			printf("seeking on intercom for client ");
			print_ip(&data->address, "\n");
		}
		intercom_seek(&l3ctx.intercom_ctx, (const struct in6_addr*) &(data->address));
	}
}

void ipcheck_task(void *d) {
	struct ip_task *data = d;

	struct entry *e = find_entry(data->ctx, &data->address);

	if (!e) {
		return;
	}

	char str[INET6_ADDRSTRLEN] = "";
	inet_ntop(AF_INET6, &data->address, str, sizeof str);
	if (l3ctx.debug)
		printf("running an ipcheck on %s\n", str);

	e->check_task = NULL;

	if (ipcheck(data->ctx, e)) {
		schedule_ipcheck(data->ctx, e);
	}
}

bool ipcheck(ipmgr_ctx *ctx, struct entry *e) {
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	struct timespec then = now;
	then.tv_sec -= PACKET_TIMEOUT;

	for (int i = 0; i < VECTOR_LEN(e->packets); i++) {
		struct packet *p = VECTOR_INDEX(e->packets, i);

		if (timespec_cmp(p->timestamp, then) <= 0) {
			if (l3ctx.debug) {
				printf("deleting old packet with destination ");
				print_ip(&e->address, "\n");
			}

			free(p->data);
			free(p);
			VECTOR_DELETE(e->packets, i);
			i--;
		}
	}

	then = now;
	then.tv_sec -= SEEK_TIMEOUT;

	if (VECTOR_LEN(e->packets) == 0 && timespec_cmp(e->timestamp, then) <= 0) {
		VECTOR_FREE(e->packets);
		delete_entry(ctx, &e->address);
		return false;
	}

	return true;
}

void ipmgr_handle_in(ipmgr_ctx *ctx, int fd) {
	ssize_t count;
	uint8_t buf[1500];

	while (1) {
		count = read(fd, buf, sizeof buf);

		if (count == -1) {
			/* If errno == EAGAIN, that means we have read all
			   data. So go back to the main loop. */
			if (errno != EAGAIN) {
				perror("read");
			}
			break;
		} else if (count == 0) {
			/* End of file. The remote has closed the
			   connection. */
			break;
		}

		// so why again ware we not allowing packets with less than 40 bytes?
		if (count < 40)
			continue;

		// We're only interested in ip6 packets
		if ((buf[0] & 0xf0) != 0x60)
			continue;

		handle_packet(ctx, buf, count);
	}
}

void ipmgr_handle_out(ipmgr_ctx *ctx, int fd) {
	ssize_t count;

	while (1) {
		if (VECTOR_LEN(ctx->output_queue) == 0)
			break;

		struct packet *packet = &VECTOR_INDEX(ctx->output_queue, 0);
		count = write(fd, packet->data, packet->len);

		// TODO refactor to use epoll. do we have to put the packet back in case of EAGAIN?
		free(packet->data);
		VECTOR_DELETE(ctx->output_queue, 0);

		if (count == -1) {
			if (errno != EAGAIN)
				perror("Could not send packet to newly visible client");

			break;
		}
	}
}

void ipmgr_route_appeared(ipmgr_ctx *ctx, const struct in6_addr *destination) {
	struct entry *e = find_entry(ctx, destination);

	if (!e)
		return;

	for (int i = 0; i < VECTOR_LEN(e->packets); i++) {
		struct packet *p = VECTOR_INDEX(e->packets, i);
		VECTOR_ADD(ctx->output_queue, *p);
	}

	VECTOR_FREE(e->packets);


	delete_entry(ctx, destination);

	ipmgr_handle_out(ctx, ctx->fd);
}


bool ipmgr_init(ipmgr_ctx *ctx, char *tun_name, unsigned int mtu) {
	return tun_open(ctx, tun_name, mtu, "/dev/net/tun");
}
