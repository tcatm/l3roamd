#pragma once

#include "ipmgr.h"
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <linux/rtnetlink.h>

typedef struct {
	struct l3ctx *l3ctx;
	int fd;
	int unreachfd;
	int nsfd;
	bool ok;
	uint8_t mac[6];
	char *clientif;
	unsigned int ifindex;
} icmp6_ctx;

void icmp6_handle_in(icmp6_ctx *ctx, int fd);
void icmp6_handle_ns_in(icmp6_ctx *ctx, int fd);
void icmp6_send_solicitation(icmp6_ctx *ctx, const struct in6_addr *addr);
void icmp6_init(icmp6_ctx *ctx);
void icmp6_interface_changed(icmp6_ctx *ctx, int type, const struct ifinfomsg *msg);
void icmp6_send_dest_unreachable(const struct in6_addr *addr, const struct packet *data, int fd);
void icmp6_setup_interface(icmp6_ctx *ctx);
