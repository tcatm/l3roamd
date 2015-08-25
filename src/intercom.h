#pragma once

#include "l3roamd.h"

#include <stdint.h>

enum {INTERCOM_SEEK, INTERCOM_CLIENT};

typedef struct __attribute__((__packed__)) {
  uint8_t ttl;
  uint32_t nonce;
  uint8_t sender[16];
  uint8_t type;
} intercom_packet_hdr;

typedef struct __attribute__((__packed__)) {
  intercom_packet_hdr hdr;
  uint8_t address[16];
} intercom_packet_seek;

typedef struct {
  struct sockaddr_in6 *groupaddr;
  VECTOR(intercom_packet_hdr) recent_packets;
} intercom_ctx;

void intercom_recently_seen_add(intercom_ctx *ctx, intercom_packet_hdr *hdr);
void intercom_send_packet(intercom_ctx *ctx, int fd, uint8_t *packet, ssize_t packet_len);
void intercom_seek(struct l3ctx *ctx, const struct in6_addr *address);

extern void intercom_init(struct l3ctx *ctx, const char *ifname);
extern void intercom_handle_in(struct l3ctx *ctx, int fd);
