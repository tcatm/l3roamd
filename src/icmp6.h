#pragma once

#include "l3roamd.h"

void icmp6_handle_in(struct l3ctx *ctx, int fd);
void icmp6_handle_ns_in(struct l3ctx *ctx, int fd);
void icmp6_send_solicitation(struct l3ctx *ctx, const struct in6_addr *addr);
void icmp6_init(struct l3ctx *ctx);
void icmp6_interface_changed(struct l3ctx *ctx, int type, const struct ifinfomsg *msg);
void icmp6_setup_interface(struct l3ctx *ctx);
