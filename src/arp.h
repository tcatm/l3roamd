/*
 * This file is part of project l3roamd. It's copyrighted by the contributors
 * recorded in the version control history of the file, available from
 * its original location https://github.com/freifunk-gluon/l3roamd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#pragma once

#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include "common.h"

#define ARP_REQUEST 1
#define ARP_REPLY 2

struct __attribute__((packed)) arp_packet {
	uint16_t hd;
	uint16_t pr;
	uint8_t hdl;
	uint8_t prl;
	uint16_t op;
	uint8_t sha[ETH_ALEN];
	uint8_t spa[4];
	uint8_t dha[ETH_ALEN];
	uint8_t dpa[4];
};

typedef struct {
	struct in6_addr prefix;
	char *clientif;
	unsigned int ifindex;
	int fd;
	uint8_t mac[ETH_ALEN];
} arp_ctx;

void arp_handle_in(arp_ctx *ctx, int fd);
void arp_send_request(arp_ctx *ctx, const struct in6_addr *addr);
void arp_init(arp_ctx *ctx);
void arp_interface_changed(arp_ctx *ctx, int type, const struct ifinfomsg *msg);
void arp_setup_interface(arp_ctx *ctx);
