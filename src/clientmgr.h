#pragma once

#include "vector.h"
#include "linkedlist.h"
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <time.h>

#define IP_CHECKCLIENT_TIMEOUT 5

struct prefix {
  struct in6_addr prefix;
  int plen;
};

struct client_ip {
  struct in6_addr address;
  struct timespec lastseen;
};

struct client {
  unsigned int ifindex;
  bool ours;
  bool check_pending;
  uint8_t mac[6];
  struct timespec lastseen;
  VECTOR(struct client_ip) addresses;
};

typedef struct {
  struct l3ctx *l3ctx;
  struct prefix prefix;
  unsigned int export_table;
  VECTOR(struct client) clients;
} clientmgr_ctx;

struct l3ctx;

struct client_task {
  clientmgr_ctx *ctx;
  struct l3ctx *l3ctx;
  uint8_t mac[6];
};

void clientmgr_add_address(clientmgr_ctx *ctx, struct in6_addr *address, uint8_t *mac, unsigned int ifindex);
void clientmgr_update_client_routes(clientmgr_ctx *ctx, unsigned int table, struct client *client);
void clientmgr_handle_info(clientmgr_ctx *ctx, struct client *client);
void clientmgr_handle_claim(clientmgr_ctx *ctx, uint32_t lastseen, uint8_t *mac, const struct in6_addr *sender);
void clientmgr_add_client(clientmgr_ctx *ctx, uint8_t *mac, unsigned int ifindex);
void print_client(struct client *client);
void clientmgr_pruneclient_task(void *d);
void clientmgr_checkclient_task(void *d);
void clientmgr_remove_route(clientmgr_ctx *ctx, struct client *client, struct client_ip *ip);
