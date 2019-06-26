/*
 * This file is part of project l3roamd. It's copyrighted by the contributors
 * recorded in the version control history of the file, available from
 * its original location https://github.com/freifunk-gluon/l3roamd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#pragma once

#include "common.h"
#include "if.h"

#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <stdbool.h>

#define KERNEL_INFINITY 0xffff
#define ROUTE_PROTO 158

#ifndef NDA_RTA
#define NDA_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif

static inline __u32 rta_getattr_u32(const struct rtattr *rta) {
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
	struct in6_addr src_prefix;
	struct in6_addr gw;
	int plen;
	int src_plen; /* no source prefix <=> src_plen == 0 */
	int metric;
	int proto;
	unsigned int ifindex;
	unsigned int table;
};

typedef struct {
	char *clientif;
	char *client_bridge;
	int fd;
	int clientif_index;
	int client_bridge_index;
	bool nl_disabled;
	uint8_t bridge_mac[ETH_ALEN];
} routemgr_ctx;

void handle_route(routemgr_ctx *ctx, struct kernel_route *route);
int parse_kernel_route_rta(struct rtmsg *rtm, int len,
			   struct kernel_route *route);
void routemgr_handle_in(routemgr_ctx *ctx, int fd);
void routemgr_init(routemgr_ctx *ctx);
void routemgr_probe_neighbor(routemgr_ctx *ctx, const int ifindex,
			     struct in6_addr *address, uint8_t mac[ETH_ALEN]);
void routemgr_insert_neighbor(routemgr_ctx *ctx, const int ifindex,
			      struct in6_addr *address, uint8_t mac[ETH_ALEN]);
void routemgr_remove_neighbor(routemgr_ctx *ctx, const int ifindex,
			      struct in6_addr *address, uint8_t mac[ETH_ALEN]);
void routemgr_insert_route(routemgr_ctx *ctx, const int table,
			   const int ifindex, struct in6_addr *address,
			   const int prefix_length);
void routemgr_remove_route(routemgr_ctx *ctx, const int table,
			   struct in6_addr *address, const int prefix_length);
void routemgr_insert_neighbor4(routemgr_ctx *ctx, const int ifindex,
			       struct in_addr *address, uint8_t mac[ETH_ALEN]);
void routemgr_remove_neighbor4(routemgr_ctx *ctx, const int ifindex,
			       struct in_addr *address, uint8_t mac[ETH_ALEN]);
void routemgr_insert_route4(routemgr_ctx *ctx, const int table,
			    const int ifindex, struct in_addr *address,
			    const int prefix_length);
void routemgr_remove_route4(routemgr_ctx *ctx, const int table,
			    struct in_addr *address, const int prefix_length);
void rtnl_add_address(routemgr_ctx *ctx, struct in6_addr *address);
void rtnl_remove_address(routemgr_ctx *ctx, struct in6_addr *address);

void rtmgr_client_remove_address(struct in6_addr *dst_address);
