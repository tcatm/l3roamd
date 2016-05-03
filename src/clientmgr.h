#pragma once

#include "vector.h"
#include "linkedlist.h"
#include "taskqueue.h"
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <time.h>

#define IP_CHECKCLIENT_TIMEOUT 5
#define NA_TIMEOUT 10
#define CLIENT_TIMEOUT 30

enum ip_state {
  IP_INACTIVE = 0,
  IP_ACTIVE,
  IP_TENTATIVE
};

struct prefix {
  struct in6_addr prefix;
  int plen;
};

struct client_ip {
  enum ip_state state;
  struct in6_addr address;
  struct timespec timestamp;
};

struct client {
  unsigned int ifindex;
  taskqueue_t *check_task;
  struct timespec timeout;
  uint8_t mac[6];
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
void clientmgr_notify_mac(clientmgr_ctx *ctx, uint8_t *mac, unsigned int ifindex);
void clientmgr_handle_claim(clientmgr_ctx *ctx, const struct in6_addr *sender, uint8_t mac[6]);
void clientmgr_handle_info(clientmgr_ctx *ctx, struct client *foreign_client);
