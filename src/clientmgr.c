#include "clientmgr.h"
#include "routes.h"

#include <stdio.h>
#include <string.h>
#include <time.h>


static bool prefix_contains(const struct prefix *prefix, struct in6_addr *addr) {
  int plen = prefix->plen;

  for (int i = 0; i < 16; i++) {
    int mask = ~((1<<(8 - (plen > 8 ? 8 : plen))) - 1);

    if ((addr->s6_addr[i] & mask) != prefix->prefix.s6_addr[i])
      return false;

    plen -= 8;

    if (plen < 0)
      plen = 0;
  }
  return true;
}

struct client_ip *clientmgr_get_client_ip(struct client *client, const struct in6_addr *address) {
  for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
    struct client_ip *e = &VECTOR_INDEX(client->addresses, i);

    if (memcmp(address, &e->address, sizeof(struct in6_addr)) == 0)
      return e;
  }

  return NULL;
}

void clientmgr_delete_client_ip(struct client *client, const struct in6_addr *address) {
  for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
    struct client_ip *e = &VECTOR_INDEX(client->addresses, i);

    if (memcmp(address, &e->address, sizeof(struct in6_addr)) == 0) {
      VECTOR_DELETE(client->addresses, i);
      break;
    }
  }
}

struct client *clientmgr_get_client(clientmgr_ctx *ctx, const uint8_t mac[6]) {
  for (int i = 0; i < VECTOR_LEN(ctx->clients); i++) {
    struct client *e = &VECTOR_INDEX(ctx->clients, i);

    if (memcmp(mac, e->mac, sizeof(uint8_t) * 6) == 0)
      return e;
  }

  return NULL;
}

void clientmgr_delete_client(clientmgr_ctx *ctx, const uint8_t mac[6]) {
  // TODO free addresses vector here?
  for (int i = 0; i < VECTOR_LEN(ctx->clients); i++) {
    struct client *e = &VECTOR_INDEX(ctx->clients, i);

    if (memcmp(mac, e->mac, sizeof(uint8_t) * 6) == 0) {
      VECTOR_DELETE(ctx->clients, i);
      break;
    }
  }
}

void clientmgr_init(clientmgr_ctx *ctx) {
  // timer socket bauen
}

void clientmgr_add_client(clientmgr_ctx *ctx, struct l3ctx *l3ctx, uint8_t *mac) {
  printf("A client roamed to us\n");

  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);

  struct client *client = clientmgr_get_client(ctx, mac);

  // ignore unknown clients
  if (client == NULL)
    return;

  if (client->ours)
    return;

  client->lastseen = now;
  client->ours = true;

  print_client(client);

  intercom_claim(&l3ctx->intercom_ctx, client);
  // TODO timer auf lastseen und so schedulen

  clientmgr_update_client_routes(l3ctx, ctx->export_table, client);
}

void clientmgr_add_address(clientmgr_ctx *ctx, struct l3ctx *l3ctx, struct in6_addr *address, uint8_t *mac) {
  // TODO sicherstellen, dass IPs nur jeweils einem Client zugeordnet sind

  printf("Add address 0\n");
  char str[INET6_ADDRSTRLEN];


  inet_ntop(AF_INET6, address, str, INET6_ADDRSTRLEN);
  printf("Address: %s\n", str);

    inet_ntop(AF_INET6, &ctx->prefix.prefix, str, INET6_ADDRSTRLEN);
    printf("Prefix: %s/%i\n", str, ctx->prefix.plen);



  if (!prefix_contains(&ctx->prefix, address))
    return;

  printf("Add address 1\n");

  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);

  struct client *client = clientmgr_get_client(ctx, mac);

  if (client == NULL) {
    struct client _client = { .ours = true };
    memcpy(_client.mac, mac, sizeof(uint8_t) * 6);
    VECTOR_ADD(ctx->clients, _client);
    client = &VECTOR_INDEX(ctx->clients, VECTOR_LEN(ctx->clients) - 1);
  }

  struct client_ip *ip = clientmgr_get_client_ip(client, address);

  if (ip == NULL) {
    struct client_ip _ip = {};
    memcpy(&_ip.address, address, sizeof(struct in6_addr));
    VECTOR_ADD(client->addresses, _ip);
    ip = &VECTOR_INDEX(client->addresses, VECTOR_LEN(client->addresses) - 1);
  }

  char target[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, address, target, INET6_ADDRSTRLEN);
  printf("Noticed client: %s\n", target);

  client->ours = true;
  client->lastseen = now;
  ip->lastseen = now;

  print_client(client);

  intercom_claim(&l3ctx->intercom_ctx, client);
  // TODO timer auf lastseen und so schedulen

  clientmgr_update_client_routes(l3ctx, ctx->export_table, client);
}

// TODO funktion evtl. nach routes.c?
void clientmgr_update_client_routes(struct l3ctx *ctx, unsigned int table, struct client *client) {
  // TODO ifindex auslagern, netlink socket und so
  unsigned int ifindex = if_nametoindex(ctx->clientif);

  for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
    struct client_ip *e = &VECTOR_INDEX(client->addresses, i);

    struct kernel_route route = {
      .plen = 128,
      .proto = 23,
      .ifindex = ifindex,
      .table = table
    };

    memcpy(route.prefix, e->address.s6_addr, 16);

    insert_route(ctx, &route, client->mac);
  }
}

// TODO funktion evtl. nach routes.c?
void clientmgr_remove_client_routes(struct l3ctx *ctx, unsigned int table, struct client *client) {
  // TODO ifindex auslagern, netlink socket und so
  printf("Removing routes\n");
  unsigned int ifindex = if_nametoindex(ctx->clientif);

  for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
    struct client_ip *e = &VECTOR_INDEX(client->addresses, i);

    struct kernel_route route = {
      .plen = 128,
      .proto = 23,
      .ifindex = ifindex,
      .table = table
    };

    memcpy(route.prefix, e->address.s6_addr, 16);

    remove_route(ctx, &route);
  }
}

void clientmgr_handle_claim(clientmgr_ctx *ctx, struct l3ctx *l3ctx, struct client *foreign_client, struct in6_addr *sender) {
  struct client *client = clientmgr_get_client(ctx, foreign_client->mac);

  printf("Received foreign client\n");

  char str[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, sender, str, INET6_ADDRSTRLEN);
  printf("Sender %s\n", str);

  print_client(foreign_client);

  if (client == NULL) {
    VECTOR_ADD(ctx->clients, *foreign_client);
    return;
  }

  if (!client->ours)
    return;

  if (client->lastseen.tv_sec > foreign_client->lastseen.tv_sec) {
    intercom_claim(&l3ctx->intercom_ctx, client);
    return;
  }

  clientmgr_remove_client_routes(l3ctx, ctx->export_table, client);

  print_client(client);

  clientmgr_delete_client(ctx, foreign_client->mac);
  VECTOR_ADD(ctx->clients, *foreign_client);

  // TODO timer setzen!
}

void print_client(struct client *client) {
  printf("Client %02x:%02x:%02x:%02x:%02x:%02x\n", client->mac[0], client->mac[1],
                                                   client->mac[2], client->mac[3],
                                                   client->mac[4], client->mac[5]);
  printf("  Adresses\n");

  for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
    struct client_ip *e = &VECTOR_INDEX(client->addresses, i);

    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &e->address, str, INET6_ADDRSTRLEN);
    printf("  - %s\n", str);
  }
}
