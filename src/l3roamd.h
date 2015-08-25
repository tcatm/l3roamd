#pragma once

#include "vector.h"
#include "linkedlist.h"

#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

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

struct prefix {
  struct in6_addr prefix;
  int plen;
};

struct l3ctx {
  int timerfd;
  struct tun_iface tun;
  int rtnl_sock;
  int icmp6fd;
  int intercomfd;
  const char *clientif;
  uint8_t icmp6mac[6];
  int export_table;
  VECTOR(struct entry) addrs;
  LinkedList output_queue;
  struct prefix clientprefix;
  void *intercom_ctx;
};

void schedule(struct l3ctx *ctx);
void handle_packet(struct l3ctx *ctx, uint8_t packet[], ssize_t packet_len);
void neighbour_discovered(struct l3ctx *ctx, struct in6_addr *addr, uint8_t mac[6]);
extern void delete_entry(struct l3ctx *ctx, const struct in6_addr *k);
extern void drain_output_queue(struct l3ctx *ctx);
extern struct ip_entry *find_entry(struct l3ctx *ctx, const struct in6_addr *k);
extern void establish_route(struct l3ctx *ctx, const struct in6_addr *addr);
