#pragma once

#include "vector.h"
#include "linkedlist.h"
#include "intercom.h"
#include "wifistations.h"
#include "clientmgr.h"

#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

struct tun_iface {
  int fd;
  char *name;
  uint16_t mtu;
};

struct ip_entry {
  time_t timeout;
  uint8_t try;
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
  int timerfd;
  struct tun_iface tun;
  int rtnl_sock;
  int icmp6fd;
  int icmp6nsfd;
  bool icmp6ok;
  const char *clientif;
  uint8_t icmp6mac[6];
  LinkedList output_queue;
  intercom_ctx intercom_ctx;
  wifistations_ctx wifistations_ctx;
  clientmgr_ctx clientmgr_ctx;
  VECTOR(struct entry) addrs;
};

void schedule(struct l3ctx *ctx);
void handle_packet(struct l3ctx *ctx, uint8_t packet[], ssize_t packet_len);
void delete_entry(struct l3ctx *ctx, const struct in6_addr *k);
void drain_output_queue(struct l3ctx *ctx);
struct ip_entry *find_entry(struct l3ctx *ctx, const struct in6_addr *k);
void establish_route(struct l3ctx *ctx, const struct in6_addr *addr);
void interfaces_changed(struct l3ctx *ctx, int type, const struct ifinfomsg *msg);
