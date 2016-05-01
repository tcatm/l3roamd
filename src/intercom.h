#pragma once

#include "vector.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

enum {INTERCOM_SEEK, INTERCOM_CLAIM, INTERCOM_INFO};

typedef struct __attribute__((__packed__)) {
  uint8_t ttl;
  uint32_t nonce;
  uint8_t type;
  uint8_t sender[16];
} intercom_packet_hdr;

typedef struct __attribute__((__packed__)) {
  intercom_packet_hdr hdr;
  uint8_t address[16];
} intercom_packet_seek;

typedef struct __attribute__((__packed__)) {
  intercom_packet_hdr hdr;
  uint8_t mac[6];
  uint32_t lastseen;
} intercom_packet_claim;

typedef struct __attribute__((__packed__)) {
  intercom_packet_hdr hdr;
  uint8_t relinquished;  // != 0 indicates that the node previously managed the client
  uint8_t mac[6];
  uint32_t lastseen;
  uint8_t num_addresses;
} intercom_packet_info;

typedef struct __attribute__((__packed__)) {
  uint8_t address[16];
  uint32_t lastseen; // relative in seconds
} intercom_packet_info_entry;

typedef struct {
  bool ok;
  unsigned int ifindex;
  char *ifname;
} intercom_if;

typedef struct {
  int fd;
  struct sockaddr_in6 groupaddr;
  struct in6_addr ip;
  VECTOR(intercom_packet_hdr) recent_packets;
  VECTOR(intercom_if) interfaces;
} intercom_ctx;

struct l3ctx;
struct client;

void intercom_recently_seen_add(intercom_ctx *ctx, intercom_packet_hdr *hdr);
void intercom_send_packet(intercom_ctx *ctx, uint8_t *packet, ssize_t packet_len);
void intercom_seek(intercom_ctx *ctx, const struct in6_addr *address);
void intercom_init(intercom_ctx *ctx);
void intercom_handle_in(intercom_ctx *ctx, struct l3ctx *l3ctx, int fd);
void intercom_add_interface(intercom_ctx *ctx, char *ifname);
void intercom_update_interfaces(intercom_ctx *ctx);
void intercom_info(intercom_ctx *ctx, const struct in6_addr *recipient, struct client *client);
void intercom_claim(intercom_ctx *ctx, uint8_t *mac, uint32_t lastseen);
