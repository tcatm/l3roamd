#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <linux/rtnetlink.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2

struct __attribute__((packed)) arp_packet {
	uint16_t hd;
	uint16_t pr;
	uint8_t hdl;
	uint8_t prl;
	uint16_t op;
	uint8_t sha[6];
	uint8_t spa[4];
	uint8_t dha[6];
	uint8_t dpa[4];
};

typedef struct {
	struct l3ctx *l3ctx;
	int fd;
	bool ok;
	struct in6_addr prefix;
	uint8_t mac[6];
	char *clientif;
	unsigned int ifindex;
} arp_ctx;

void arp_handle_in(arp_ctx *ctx, int fd);
void arp_send_request(arp_ctx *ctx, const struct in6_addr *addr);
void arp_init(arp_ctx *ctx);
void arp_interface_changed(arp_ctx *ctx, int type, const struct ifinfomsg *msg);
void arp_setup_interface(arp_ctx *ctx);
