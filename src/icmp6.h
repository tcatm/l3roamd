#pragma once

#include "l3roamd.h"

extern void icmp6_handle_in(struct l3ctx *ctx, int fd);
extern void icmp6_send_solicitation(struct l3ctx *ctx, const struct in6_addr *addr);
extern void icmp6_init(struct l3ctx *ctx);
