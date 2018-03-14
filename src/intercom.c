#include "intercom.h"
#include "error.h"
#include "l3roamd.h"
#include "if.h"
#include "icmp6.h"
#include "syscallwrappers.h"
#include "prefix.h"
#include "util.h"

#include "clientmgr.h"

#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>

#define INTERCOM_GROUP "ff02::5523"
#define INTERCOM_MAX_RECENT 100

#define CLAIM_RETRY_MAX 5

// Announce at most 32 addresses per client
#define INFO_MAX 32

void schedule_claim_retry(struct claim_task*, int timeout);

bool join_mcast(const int sock, const struct in6_addr addr, intercom_if *iface) {
	struct ipv6_mreq mreq;

	mreq.ipv6mr_multiaddr = addr;
	mreq.ipv6mr_interface = iface->ifindex;

	if (mreq.ipv6mr_interface == 0)
		goto error;

	if (setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == 0)
		return true;
	else if (errno == EADDRINUSE)
		return true;

error:
	fprintf(stderr, "Could not join multicast group on %s: ", iface->ifname);
	perror(NULL);
	return false;
}

void intercom_update_interfaces(intercom_ctx *ctx) {
	for (int i = 0; i < VECTOR_LEN(ctx->interfaces); i++) {
		intercom_if *iface = &VECTOR_INDEX(ctx->interfaces, i);

		iface->ifindex = if_nametoindex(iface->ifname);

		if (!iface->ifindex)
			continue;

		iface->ok = join_mcast(VECTOR_INDEX(ctx->interfaces, i).mcast_recv_fd, ctx->groupaddr.sin6_addr, iface);
		// TODO: do we have to re-bind?
	}
}

bool intercom_has_ifname(intercom_ctx *ctx, char *ifname) {
	for (int i = 0; i < VECTOR_LEN(ctx->interfaces); i++) {
		intercom_if *iface = &VECTOR_INDEX(ctx->interfaces, i);

		if (strcmp(ifname, iface->ifname) == 0)
			return true;
	}

	return false;
}

void intercom_add_interface(intercom_ctx *ctx, char *ifname) {
	if (intercom_has_ifname(ctx, ifname))
		return;

	int ifindex = if_nametoindex(ifname);

	intercom_if iface = {
		.ok = false,
		.ifname = ifname,
		.ifindex = ifindex
	};

	VECTOR_ADD(ctx->interfaces, iface);

}

void obtainll(const char *ifname, struct in6_addr *ret) {
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in6 *sa;
	struct in6_addr ll = {};
	
	inet_pton(AF_INET6, "fe80::", &ll);

	getifaddrs (&ifap);
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr && ifa->ifa_addr->sa_family==AF_INET6) {
			if (!memcmp(ifname, ifa->ifa_name, strlen(ifname))) {
				sa = (struct sockaddr_in6 *) ifa->ifa_addr;
				struct prefix p = { 
					.plen = 64,
					.prefix = ll
				};
				if (prefix_contains(&p, &sa->sin6_addr)) {
					memcpy(ret, &sa->sin6_addr, sizeof(struct in6_addr));
					goto end;
				}
			}
		}
	}

end:
	freeifaddrs(ifap);
}

void intercom_init(intercom_ctx *ctx) {

	struct in6_addr mgroup_addr;
	inet_pton(AF_INET6, INTERCOM_GROUP, &mgroup_addr); // TODO Fehler abfangen

	ctx->groupaddr = (struct sockaddr_in6) {
		.sin6_family = AF_INET6,
		.sin6_addr = mgroup_addr,
		.sin6_port = htons(INTERCOM_PORT),
	};

	
	// bind sockets to receive multicast
	for (int i=VECTOR_LEN(ctx->interfaces)-1;i>=0;i--) {
		int fd = socket(PF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
		if (fd < 0)
			exit_error("creating socket");

		ctx->groupaddr.sin6_scope_id = VECTOR_INDEX(ctx->interfaces, i).ifindex;
		if (bind(fd, (struct sockaddr *)&ctx->groupaddr, sizeof(ctx->groupaddr)) < 0) {
			perror("bind to multicast-address failed");
			exit(EXIT_FAILURE);
		}

		VECTOR_INDEX(ctx->interfaces, i).mcast_recv_fd = fd;
		printf("ASSIGNING fd: %i to mcast_recv_fd on interface %s\n", fd, VECTOR_INDEX(ctx->interfaces, i).ifname);

	 /*
	   // this will bind sockets meant to write data on ll-address of an interface
		if (l3ctx.debug)
			printf("binding to address on interface %s\n", VECTOR_INDEX(ctx->interfaces, i).ifname);

		int fd = socket(PF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
		if (fd < 0)
			exit_error("creating socket");

		server_addr.sin6_scope_id = VECTOR_INDEX(ctx->interfaces, i).ifindex;
		obtainll(VECTOR_INDEX(ctx->interfaces, i).ifname, &server_addr.sin6_addr);

		if (bind(fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in6)) < 0) {
			perror("bind to ll-address failed");
			exit(EXIT_FAILURE);
		}

		VECTOR_ADD(ctx->send_fd, fd);
		*/
	}

	struct sockaddr_in6 server_addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(INTERCOM_PORT),
	};

	ctx->unicast_nodeip_fd = socket(PF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (ctx->unicast_nodeip_fd < 0)
		exit_error("creating socket for intercom on node-IP");

	memcpy(&server_addr.sin6_addr, ctx->ip.s6_addr, 16);
	if (bind(ctx->unicast_nodeip_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("bind socket to node-IP failed");
		exit(EXIT_FAILURE);
	}

	printf("ASSIGNING fd: %i to unicast_nodeip_fd\n", ctx->unicast_nodeip_fd);

	intercom_update_interfaces(ctx);
}

void intercom_seek(intercom_ctx *ctx, const struct in6_addr *address) {
	intercom_packet_seek packet;

	packet.hdr = (intercom_packet_hdr) {
		.type = INTERCOM_SEEK,
		.ttl = 255,
	};

	obtainrandom(&(packet.hdr.nonce), sizeof(uint32_t), 0);
	memcpy(&packet.hdr.sender, &ctx->ip, 16);
	memcpy(&packet.address, address, 16);

	intercom_recently_seen_add(ctx, &packet.hdr);

	intercom_send_packet(ctx, (uint8_t*)&packet, sizeof(packet));
}

bool intercom_send_packet_unicast(intercom_ctx *ctx, const struct in6_addr *recipient, uint8_t *packet, ssize_t packet_len) {
	struct sockaddr_in6 addr = (struct sockaddr_in6) {
		.sin6_family = AF_INET6,
		.sin6_port = htons(INTERCOM_PORT),
		.sin6_addr = *recipient
	};

	ssize_t rc = sendto(ctx->unicast_nodeip_fd, packet, packet_len, 0, (struct sockaddr*)&addr, sizeof(addr));
	if (l3ctx.debug) {
		printf("sent intercom packet rc: %zi to ", rc);
		print_ip(recipient, "\n");
	}
	if (rc < 0)
		perror("sendto failed");

	return rc >= 0;
}

void intercom_send_packet(intercom_ctx *ctx, uint8_t *packet, ssize_t packet_len) {
	for (int i = 0; i < VECTOR_LEN(ctx->interfaces); i++) {
		intercom_if *iface = &VECTOR_INDEX(ctx->interfaces, i);
//		int fd = VECTOR_INDEX(ctx->interfaces, i).mcast_send_fd ;
		int fd = ctx->unicast_nodeip_fd;

		if (!iface->ok)
			continue;

		struct sockaddr_in6 _groupaddr = {};
		memcpy(&_groupaddr, &ctx->groupaddr, sizeof(struct sockaddr_in6));

		_groupaddr.sin6_scope_id = iface->ifindex;

		ssize_t rc = sendto(fd, packet, packet_len, 0, (struct sockaddr*)&_groupaddr, sizeof(struct sockaddr_in6));
		if (l3ctx.debug) {
			char str[INET6_ADDRSTRLEN+1];
			inet_ntop(AF_INET6, &_groupaddr.sin6_addr, str, INET6_ADDRSTRLEN);
			printf("sent intercom packet to %s on iface %s rc: %zi\n",str , iface->ifname,rc);
		}
		if (rc < 0)
			iface->ok = false;
	}
}

bool intercom_recently_seen(intercom_ctx *ctx, intercom_packet_hdr *hdr) {
	for (int i = 0; i < VECTOR_LEN(ctx->recent_packets); i++) {
		intercom_packet_hdr *ref_hdr = &VECTOR_INDEX(ctx->recent_packets, i);

		if (ref_hdr->nonce == hdr->nonce && ref_hdr->type == hdr->type)
			return true;
	}
	return false;
}

void intercom_recently_seen_add(intercom_ctx *ctx, intercom_packet_hdr *hdr) {
	if (VECTOR_LEN(ctx->recent_packets) > INTERCOM_MAX_RECENT)
		VECTOR_DELETE(ctx->recent_packets, 0);

	VECTOR_ADD(ctx->recent_packets, *hdr);
}

void intercom_handle_seek(intercom_ctx *ctx, intercom_packet_seek *packet) {
	struct in6_addr *address = (struct in6_addr *)packet->address;

	printf("\x1b[36mSEEK: Looking for ");
	print_ip(address, "\x1b[0m\n");

	if (clientmgr_is_ipv4(CTX(clientmgr), address))
		arp_send_request(CTX(arp), address);
	else
		icmp6_send_solicitation(CTX(icmp6), address);
}

void intercom_handle_claim(intercom_ctx *ctx, intercom_packet_claim *packet) {
	struct in6_addr sender;

	memcpy(&sender.s6_addr, &packet->hdr.sender, sizeof(uint8_t) * 16);
	printf("handling claim from: ");
	print_ip(&sender, "\n");

	clientmgr_handle_claim(CTX(clientmgr), &sender, packet->mac);
}



/** Finds the entry for a peer with a specified ID in the array \e ctx.peers */
/*
static int peer_id_cmp(fastd_peer_t *const *a, fastd_peer_t *const *b) {
if ((*a)->id == (*b)->id)
return 0;
else if ((*a)->id < (*b)->id)
return -1;
else
return 1;
}
static fastd_peer_t ** peer_p_find_by_id(uint64_t id) {
	fastd_peer_t key = {.id = id};
	fastd_peer_t *const keyp = &key;

	return VECTOR_BSEARCH(&keyp, ctx.peers, peer_id_cmp);
}
*/

bool find_repeatable_claim(uint8_t mac[6], int *index) {
	// TODO: replace this with VECTOR_BSEARCH -- see the example above
	for (*index=0;*index<VECTOR_LEN(l3ctx.intercom_ctx.repeatable_claims);(*index)++) {
		struct client *client = &VECTOR_INDEX(l3ctx.intercom_ctx.repeatable_claims, *index);
		if (!memcmp(client->mac, mac, 6))
			return true;
	}
	return false;
}


void intercom_handle_info(intercom_ctx *ctx, intercom_packet_info *packet) {
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	struct client client = { 0 };

	memcpy(client.mac, &packet->mac, sizeof(uint8_t) * 6);

	printf("handling info with %i addresses for client ", packet->num_addresses);
	print_client(&client);

	struct in6_addr sender;
	memcpy(&sender.s6_addr, &packet->hdr.sender, sizeof(uint8_t) * 16);
	print_ip(&sender, "\n");

	int i = 0;
	if (find_repeatable_claim(packet->mac, &i))
		VECTOR_DELETE(ctx->repeatable_claims, i);

	struct client_ip ip = { 0 };
	ip.state = IP_INACTIVE;

	intercom_packet_info_entry *entry = (intercom_packet_info_entry*)((uint8_t*)(packet) + sizeof(intercom_packet_info));

	for (i = 0; i < packet->num_addresses; i++) {
		memcpy(&ip.addr.s6_addr, &entry->address, sizeof(uint8_t) * 16);
		VECTOR_ADD(client.addresses, ip);
		if (l3ctx.debug)
			print_ip(&ip.addr, " learnt from info packet\n");
		entry++;
	}

	clientmgr_handle_info(CTX(clientmgr), &client, packet->relinquished);
}

void intercom_handle_packet(intercom_ctx *ctx, uint8_t *packet, ssize_t packet_len) {
	intercom_packet_hdr *hdr = (intercom_packet_hdr*) packet;

	if (intercom_recently_seen(ctx, hdr))
		return;

	intercom_recently_seen_add(ctx, hdr);
// TODO: if the claim was for a local client, there is no need to forward the claim further.
// TODO: if the seek was for a local client, there is no need to forward the seek further.
	if (hdr->type == INTERCOM_SEEK)
		intercom_handle_seek(ctx, (intercom_packet_seek*)packet);

	if (hdr->type == INTERCOM_CLAIM)
		intercom_handle_claim(ctx, (intercom_packet_claim*)packet);

	if (hdr->type == INTERCOM_INFO)
		intercom_handle_info(ctx, (intercom_packet_info*)packet);

	hdr->ttl--;


	if (hdr->ttl > 0)
		intercom_send_packet(ctx, packet, packet_len);
}

void intercom_handle_in(intercom_ctx *ctx, int fd) {
	ssize_t count;
	uint8_t buf[ctx->mtu];
	if (l3ctx.debug)
		printf("HANDLING INTERCOM PACKET on fd %i using buffersize of %i ", fd, ctx->mtu);

	while (1) {
		count = read(fd, buf, ctx->mtu);
		if (l3ctx.debug)
			printf("- read %zi Bytes of data\n", count);
		if (count == -1) {
			/* If errno == EAGAIN, that means we have read all
				 data. So go back to the main loop.
			   if the last intercom packet was a claim for a local client, then we have just dropped the local client and will receive EBADF on the fd for the node-client-IP. This is not an error.*/
			if (errno == EBADF) {
				perror("read error - if we just dropped a local client due to this intercom packet being a claim then this is all right. otherwise there is something crazy going on. - returning to the main loop");
			}
			else if (errno != EAGAIN) {
				perror("read error - this should not happen - going back to main loop");
			}
			break;
		} else if (count == 0) {
			/* End of file. The remote has closed the
				 connection. */
			break;
		}

	// TODO if this is a claim for a local client, we should just stop iterating and get rid of the EBADF check above
		intercom_handle_packet(ctx, buf, count);
	}
}


/* recipient = NULL -> send to neighbours */
void intercom_info(intercom_ctx *ctx, const struct in6_addr *recipient, struct client *client, bool relinquished) {
	intercom_packet_info *packet = malloc(sizeof(intercom_packet_info) + INFO_MAX * sizeof(intercom_packet_info_entry));
	if (packet == NULL) {
		exit_error("could not allocate memory when generating info packet");
	}

	packet->relinquished = relinquished;
	packet->num_addresses = 0;

	char str_mac[18];

	packet->hdr = (intercom_packet_hdr) {
		.type = INTERCOM_INFO,
		.ttl = 1, // we only send info messages via unicast
	};

	obtainrandom(&(packet->hdr.nonce), sizeof(uint32_t), 0);
	memcpy(&packet->hdr.sender, &ctx->ip, 16);
	memcpy(&packet->mac, client->mac, sizeof(uint8_t) * 6);

	intercom_packet_info_entry *entry = (intercom_packet_info_entry*)((uint8_t*)(packet) + sizeof(intercom_packet_info));

	for (int i = 0; i < VECTOR_LEN(client->addresses) && packet->num_addresses < INFO_MAX; i++) {
		struct client_ip *ip = &VECTOR_INDEX(client->addresses, i);
		if (ip_is_active(ip)) {
			memcpy(&entry->address, ip->addr.s6_addr, sizeof(uint8_t) * 16);
			entry++;
			packet->num_addresses++;
		}
	}

	if (l3ctx.debug) {
		mac_addr_n2a(str_mac, client->mac);
		printf("sending info with %i addresses for client ", packet->num_addresses);
		print_client(client);
	}

	ssize_t packet_len = sizeof(intercom_packet_info) + packet->num_addresses * sizeof(intercom_packet_info_entry);

	if (recipient != NULL) {
		if (l3ctx.debug) {
			printf("sending unicast info for client %s to ",  str_mac);
			print_ip(recipient, "\n");
		}
		intercom_send_packet_unicast(ctx, recipient, (uint8_t*)packet, packet_len);
	}
	else {
		// forward packet to other l3roamd instances
		if (l3ctx.debug)
			printf("sending info for client %s to l3roamd neighbours\n", str_mac);

		intercom_recently_seen_add(ctx, &packet->hdr);
		intercom_send_packet(ctx, (uint8_t*)packet, packet_len);
	}
	free(packet);
}

void claim_retry_task(void *d) {
	struct claim_task *data = d;

	int repeatable_claim_index;
	if (!find_repeatable_claim(data->client->mac, &repeatable_claim_index))
		return;

	if (data->recipient != NULL) {
		if (l3ctx.debug) {
			printf("sending unicast claim for client %02x:%02x:%02x:%02x:%02x:%02x to ",  data->client->mac[0], data->client->mac[1], data->client->mac[2], data->client->mac[3], data->client->mac[4], data->client->mac[5]);
			print_ip(data->recipient, "\n");
		}
		if (!intercom_send_packet_unicast(&l3ctx.intercom_ctx, data->recipient, (uint8_t*)&data->packet, sizeof(data->packet)) )
			intercom_send_packet(&l3ctx.intercom_ctx, (uint8_t*)&data->packet, sizeof(data->packet)); // sending unicast did not work (node too new in the network?), fall back to multicast
	} else {
		if (l3ctx.debug) {
			printf("sending multicast claim for client %02x:%02x:%02x:%02x:%02x:%02x\n",  data->client->mac[0], data->client->mac[1], data->client->mac[2], data->client->mac[3], data->client->mac[4], data->client->mac[5]);
		}
		intercom_send_packet(&l3ctx.intercom_ctx, (uint8_t*)&data->packet, sizeof(data->packet));
	}

	if (data->retries_left > 0)
		schedule_claim_retry(data,1);
	else {
		// we have not received an info message, otherwise we would not have run out of retries => noone knew the client and it is new to the mesh.
		// => adding the special IP
		VECTOR_DELETE(l3ctx.intercom_ctx.repeatable_claims, repeatable_claim_index);
		add_special_ip(&l3ctx.clientmgr_ctx, get_client(data->client->mac));
	}

}

void free_claim_task(void *d) {
	struct claim_task *data = d;
	free(data->client);
	free(data->recipient);
	free(data);
}

void schedule_claim_retry(struct claim_task *data, int timeout) {
	struct claim_task *ndata = calloc(1, sizeof(struct claim_task));
	ndata->client = malloc(sizeof(struct client));
	memcpy(ndata->client, data->client,sizeof(struct client));
	ndata->retries_left = data->retries_left -1;
	ndata->packet = data->packet;
	ndata->recipient = NULL;
	if (data->recipient) {
		ndata->recipient = calloc(1, sizeof(struct in6_addr));
		memcpy(ndata->recipient, data->recipient, sizeof(struct in6_addr));
	}
	ndata->check_task = data->check_task;

	if (data->check_task == NULL && data->retries_left > 0)
		data->check_task = post_task(&l3ctx.taskqueue_ctx, timeout, 0, claim_retry_task, free_claim_task, ndata);
}

bool intercom_claim(intercom_ctx *ctx, const struct in6_addr *recipient, struct client *client) {
	int i;
	char mac_str[18];

	if (l3ctx.debug)
		mac_addr_n2a(mac_str, client->mac);

	if (find_repeatable_claim(client->mac, &i)) {
		if (l3ctx.debug) {
			printf("   WOULD BE RUNNING CLAIM for [%s] but a repeatable claim is still in the queue - returning\n",mac_str);
		}
		return true;
	}
	else {
		if (l3ctx.debug)
			printf("CLAIMING client [%s]\n", mac_str);
	}

	intercom_packet_claim packet;
	uint32_t nonce;

	obtainrandom(&nonce, sizeof(uint32_t), 0);

	packet.hdr = (intercom_packet_hdr) {
		.type = INTERCOM_CLAIM,
		.nonce = nonce,
		.ttl = 255,
	};

	memcpy(&packet.hdr.sender, &ctx->ip, 16);

	memcpy(&packet.mac, client->mac, 6);

	intercom_recently_seen_add(ctx, &packet.hdr);

	VECTOR_ADD(ctx->repeatable_claims, *client);

	struct claim_task data ;
	data.client = malloc(sizeof(struct client));
	memcpy(data.client, client,sizeof(struct client));
	data.retries_left = CLAIM_RETRY_MAX;
	data.packet = packet;
	data.check_task = NULL;
	data.recipient = NULL;

	if (recipient) {
		data.recipient = malloc(sizeof(struct in6_addr));
		memcpy(data.recipient, recipient, sizeof(struct in6_addr));
		packet.hdr.ttl = 1; // when sending unicast, do not continue to forward this packet at the destination
	} 

	schedule_claim_retry(&data, 0);
	free(data.recipient);
	free(data.client);
	return true;
}
