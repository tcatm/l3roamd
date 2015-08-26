#pragma once

#include "vector.h"
#include "linkedlist.h"
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <time.h>

struct prefix {
  struct in6_addr prefix;
  int plen;
};

struct client_ip {
  struct in6_addr address;
  struct timespec lastseen;
};

struct client {
  bool ours;
  uint8_t mac[6];
  struct timespec lastseen;
  VECTOR(struct client_ip) addresses;
};

typedef struct {
  struct prefix prefix;
  unsigned int export_table;
  VECTOR(struct client) clients;
} clientmgr_ctx;

struct l3ctx;

void clientmgr_add_address(clientmgr_ctx *ctx, struct l3ctx *l3ctx, struct in6_addr *address, uint8_t *mac);
void clientmgr_update_client_routes(struct l3ctx *ctx, unsigned int table, struct client *client);
void clientmgr_handle_claim(clientmgr_ctx *ctx, struct l3ctx *l3ctx, struct client *client);
void clientmgr_add_client(clientmgr_ctx *ctx, struct l3ctx *l3ctx, uint8_t *mac);
void print_client(struct client *client);
