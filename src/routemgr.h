#pragma once

#include "if.h"

#include <arpa/inet.h>
#include <linux/rtnetlink.h>

#define KERNEL_INFINITY 0xffff
#define ROUTE_PROTO 158

#ifndef NDA_RTA
#define NDA_RTA(r) \
	((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif

static inline __u32 rta_getattr_u32(const struct rtattr *rta)
{
	return *(__u32 *)RTA_DATA(rta);
}

struct nlrtreq {
	struct nlmsghdr nl;
	struct rtmsg rt;
	char buf[1024];
};

struct nlneighreq {
	struct nlmsghdr nl;
	struct ndmsg nd;
	char buf[1024];
};

struct kernel_route {
		struct in6_addr prefix;
		int plen;
		struct in6_addr src_prefix;
		int src_plen; /* no source prefix <=> src_plen == 0 */
		int metric;
		unsigned int ifindex;
		int proto;
		struct in6_addr gw;
		unsigned int table;
};

typedef struct {
	struct l3ctx *l3ctx;
	int fd;
	int clientif_index;
	char *clientif;
	char *client_bridge;
} routemgr_ctx;

void handle_route(routemgr_ctx *ctx, struct kernel_route *route);
int parse_kernel_route_rta(struct rtmsg *rtm, int len, struct kernel_route *route);
void routemgr_handle_in(routemgr_ctx *ctx, int fd);
void routemgr_init(routemgr_ctx *ctx);
void routemgr_insert_neighbor(routemgr_ctx *ctx, const int ifindex, struct in6_addr *address, uint8_t mac[6]);
void routemgr_remove_neighbor(routemgr_ctx *ctx, const int ifindex, struct in6_addr *address, uint8_t mac[6]);
void routemgr_insert_route(routemgr_ctx *ctx, const int table, const int ifindex, struct in6_addr *address, const int prefix_length);
void routemgr_remove_route(routemgr_ctx *ctx, const int table, struct in6_addr *address, const int prefix_length);
void routemgr_insert_neighbor4(routemgr_ctx *ctx, const int ifindex, struct in_addr *address, uint8_t mac[6]);
void routemgr_remove_neighbor4(routemgr_ctx *ctx, const int ifindex, struct in_addr *address, uint8_t mac[6]);
void routemgr_insert_route4(routemgr_ctx *ctx, const int table, const int ifindex, struct in_addr *address);
void routemgr_remove_route4(routemgr_ctx *ctx, const int table, struct in_addr *address);
void rtnl_add_address(routemgr_ctx *ctx, struct in6_addr *address);
void rtnl_remove_address(routemgr_ctx *ctx, struct in6_addr *address);
void routemgr_send_solicitation(routemgr_ctx *ctx, struct in6_addr *address, uint8_t *mac);
