#pragma once

#include "l3roamd.h"

#define KERNEL_INFINITY 0xffff

struct kernel_route {
    unsigned char prefix[16];
    int plen;
    unsigned char src_prefix[16];
    int src_plen; /* no source prefix <=> src_plen == 0 */
    int metric;
    unsigned int ifindex;
    int proto;
    unsigned char gw[16];
    unsigned int table;
};

typedef struct {
  struct l3ctx *l3ctx;
  int fd;
} routemgr_ctx;

int rtnl_addattr(struct nlmsghdr *n, int maxlen, int type, void *data, int datalen);
void handle_route(struct l3ctx *ctx, struct kernel_route *route);
int parse_kernel_route_rta(struct rtmsg *rtm, int len, struct kernel_route *route);
void rtnl_handle_in(struct l3ctx *ctx, int fd);
void rtnl_init(struct l3ctx *ctx);
void route_insert(struct l3ctx *ctx, const struct kernel_route *route, uint8_t *mac);
void route_remove(struct l3ctx *ctx, const struct kernel_route *route);
