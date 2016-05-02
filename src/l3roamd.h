#pragma once

#include "vector.h"
#include "linkedlist.h"
#include "intercom.h"
#include "wifistations.h"
#include "clientmgr.h"
#include "taskqueue.h"
#include "icmp6.h"

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/rtnetlink.h>

struct tun_iface {
  int fd;
  char *name;
  uint16_t mtu;
};

struct ip_entry {
  VECTOR(struct packet*) packets;
};

struct packet {
  ssize_t len;
  uint8_t *data;
};

struct entry {
  struct in6_addr k;
  struct ip_entry *v;
};

struct l3ctx {
  struct tun_iface tun; // FIXME own context
  int rtnl_sock; // FIXME move to own context
  LinkedList output_queue; // FIXME own context
  taskqueue_ctx taskqueue_ctx;
  intercom_ctx intercom_ctx;
  wifistations_ctx wifistations_ctx;
  clientmgr_ctx clientmgr_ctx;
  icmp6_ctx icmp6_ctx;
  VECTOR(struct entry) addrs; // FIXME own context
};

void handle_packet(struct l3ctx *ctx, uint8_t packet[], ssize_t packet_len);
void delete_entry(struct l3ctx *ctx, const struct in6_addr *k);
void drain_output_queue(struct l3ctx *ctx);
struct ip_entry *find_entry(struct l3ctx *ctx, const struct in6_addr *k);
void establish_route(struct l3ctx *ctx, const struct in6_addr *addr);
void interfaces_changed(struct l3ctx *ctx, int type, const struct ifinfomsg *msg);

#define CTX(tgt) (&ctx->l3ctx->tgt ## _ctx)
