#include "icmp6.h"
#include "l3roamd.h"

#include <sys/ioctl.h>
#include <string.h>
#include <error.h>
#include <netinet/ip.h>
#include <netinet/icmp6.h>

static inline int setsockopt_int(int socket, int level, int option, int value) {
	return setsockopt(socket, level, option, &value, sizeof(value));
}

void icmp6_init(struct l3ctx *ctx) {
  int fd = socket(PF_INET6, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMPV6);
  setsockopt_int(fd, IPPROTO_RAW, IPV6_CHECKSUM, 2);
  setsockopt_int(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, 255);
	setsockopt_int(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, 1);
  setsockopt_int(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, 1);

	struct icmp6_filter filter;
	ICMP6_FILTER_SETBLOCKALL(&filter);
	ICMP6_FILTER_SETPASS(ND_NEIGHBOR_ADVERT, &filter);
	setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter));

  ctx->icmp6fd = fd;

	icmp6_setup_interface(ctx);
}

void icmp6_setup_interface(struct l3ctx *ctx) {
	ctx->icmp6ok = false;

	int rc = setsockopt(ctx->icmp6fd, SOL_SOCKET, SO_BINDTODEVICE, ctx->clientif, strnlen(ctx->clientif, IFNAMSIZ-1));

	printf("Setting up icmp6 interface: %i\n", rc);

	if (rc < 0)
		return;

	struct ifreq req = {};
	strncpy(req.ifr_name, ctx->clientif, IFNAMSIZ-1);
	ioctl(ctx->icmp6fd, SIOCGIFHWADDR, &req);
	memcpy(ctx->icmp6mac, req.ifr_hwaddr.sa_data, 6);

	ctx->icmp6ok = true;
}

void icmp6_interface_changed(struct l3ctx *ctx, int type, const struct ifinfomsg *msg) {
	char ifname[IFNAMSIZ];

	if (if_indextoname(msg->ifi_index, ifname) == NULL)
		return;

	if (strcmp(ifname, ctx->clientif) != 0)
		return;

	printf("icmp6 interface change detected\n");

	switch (type) {
    case RTM_NEWLINK:
    case RTM_SETLINK:
			icmp6_setup_interface(ctx);
      break;

    case RTM_DELLINK:
			ctx->icmp6ok = false;
      break;
  }
}

struct __attribute__((__packed__)) sol_packet {
	struct nd_neighbor_solicit hdr;
	struct nd_opt_hdr opt;
	uint8_t hw_addr[6];
};

struct __attribute__((__packed__)) adv_packet {
	struct nd_neighbor_advert hdr;
	struct nd_opt_hdr opt;
	uint8_t hw_addr[6];
};

void icmp6_handle_in(struct l3ctx *ctx, int fd) {
printf("icmp\n");

  struct msghdr msghdr;
	memset (&msghdr, 0, sizeof (msghdr));

	struct adv_packet packet;
	char cbuf[CMSG_SPACE (sizeof (int))];

	struct iovec iov =	{
		.iov_base = &packet,
		.iov_len = sizeof(packet)
	};

	struct msghdr hdr =	{
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof (cbuf)
	};

	ssize_t rc = recvmsg(ctx->icmp6fd, &hdr, 0);

	if (rc == -1)
		return;

	if (packet.hdr.nd_na_hdr.icmp6_type != ND_NEIGHBOR_ADVERT)
		return;

	if (packet.hdr.nd_na_hdr.icmp6_code != 0)
		return;

	neighbour_discovered(ctx, &packet.hdr.nd_na_target, packet.hw_addr);
}

void icmp6_send_solicitation(struct l3ctx *ctx, const struct in6_addr *addr) {
  struct sol_packet packet;

  packet.hdr.nd_ns_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;
  packet.hdr.nd_ns_hdr.icmp6_code = 0;
  packet.hdr.nd_ns_hdr.icmp6_cksum = 0;
  packet.hdr.nd_ns_reserved = 0;
  memcpy(&packet.hdr.nd_ns_target, addr, 16);

  packet.opt.nd_opt_type = ND_OPT_SOURCE_LINKADDR;
	packet.opt.nd_opt_len = 1;
  memcpy(packet.hw_addr, ctx->icmp6mac, 6);

  struct sockaddr_in6 dst = {};
  dst.sin6_family = AF_INET6;
  memcpy(&dst.sin6_addr, addr, 16);
  memcpy(&dst.sin6_addr, "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff", 13);

  char str[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &dst.sin6_addr, str, sizeof str);
  printf("Send NS to %s\n", str);

  sendto(ctx->icmp6fd, &packet, sizeof(packet), 0, &dst, sizeof(dst));
}
