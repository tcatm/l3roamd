#include "clientmgr.h"
#include "routes.h"
#include "icmp6.h"
#include "timespec.h"

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
}

void clientmgr_schedule_client_task(clientmgr_ctx *ctx, struct l3ctx *l3ctx, unsigned int timeout, void (*f)(void *), uint8_t mac[6]) {
  struct client_task *data = calloc(1, sizeof(struct client_task));

  data->ctx = ctx;
  data->l3ctx = l3ctx;
  memcpy(data->mac, mac, 6);

  post_task(&l3ctx->taskqueue_ctx, timeout, f, data);
}

void clientmgr_add_client(clientmgr_ctx *ctx, struct l3ctx *l3ctx, uint8_t *mac) {
  printf("A client roamed to us\n");

  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);

  struct client *client = clientmgr_get_client(ctx, mac);

  if (client == NULL) {
    struct client _client = { .ours = true };
    memcpy(_client.mac, mac, sizeof(uint8_t) * 6);
    VECTOR_ADD(ctx->clients, _client);
    client = &VECTOR_INDEX(ctx->clients, VECTOR_LEN(ctx->clients) - 1);
    client = &_client;
  } else if (client->ours) {
    return;
  }

  client->lastseen = now;
  client->ours = true;

  print_client(client);

  intercom_claim(&l3ctx->intercom_ctx, mac, now.tv_nsec);

  clientmgr_schedule_client_task(ctx, l3ctx, IP_CHECKCLIENT_TIMEOUT, clientmgr_checkclient_task, client->mac);

  clientmgr_update_client_routes(l3ctx, ctx->export_table, client);
}

void clientmgr_pruneclient_task(void *d) {
  struct client_task *data = d;

  struct client *client = clientmgr_get_client(data->ctx, data->mac);

  if (client == NULL)
    return;

  if (!client->ours)
    return;

  printf("Pruning client\n");
  print_client(client);

  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);

  struct timespec then = now;
  then.tv_sec += IP_CHECKCLIENT_TIMEOUT;

  for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
    struct client_ip *ip = &VECTOR_INDEX(client->addresses, i);

    if (timespec_cmp(ip->lastseen, then) <= 0) {
      char str[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &ip->address, str, INET6_ADDRSTRLEN);
      printf("Pruning IP %s (%lds ago)\n", str, now.tv_sec - ip->lastseen.tv_sec);

      clientmgr_remove_route(data->l3ctx, data->ctx, ip);
      clientmgr_delete_client_ip(client, &ip->address);
    }
  }
}

void clientmgr_checkclient_task(void *d) {
  struct client_task *data = d;

  struct client *client = clientmgr_get_client(data->ctx, data->mac);

  if (client == NULL)
    return;

  if (!client->ours)
    return;

  printf("Checking on client\n");
  print_client(client);

  for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
    struct client_ip *ip = &VECTOR_INDEX(client->addresses, i);

    icmp6_send_solicitation(data->l3ctx, &ip->address);
  }

  clientmgr_schedule_client_task(data->ctx, data->l3ctx, 2 * IP_CHECKCLIENT_TIMEOUT, clientmgr_pruneclient_task, data->mac);
  free(d);
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

  clientmgr_schedule_client_task(ctx, l3ctx, IP_CHECKCLIENT_TIMEOUT, clientmgr_checkclient_task, client->mac);

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

void clientmgr_remove_route(struct l3ctx *l3ctx, clientmgr_ctx *ctx, struct client_ip *ip) {
  unsigned int ifindex = if_nametoindex(l3ctx->clientif);

  struct kernel_route route = {
    .plen = 128,
    .proto = 23,
    .ifindex = ifindex,
    .table = ctx->export_table
  };

  memcpy(route.prefix, ip->address.s6_addr, 16);

  remove_route(l3ctx, &route);
}

void clientmgr_remove_client_routes(struct l3ctx *l3ctx, clientmgr_ctx *ctx, struct client *client) {
  // TODO ifindex auslagern, netlink socket und so
  printf("Removing routes\n");

  for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
    struct client_ip *ip = &VECTOR_INDEX(client->addresses, i);
    clientmgr_remove_route(l3ctx, ctx, ip);
  }
}

void clientmgr_handle_info(clientmgr_ctx *ctx, struct l3ctx *l3ctx, struct client *foreign_client) {
  printf("Received client info\n");
  print_client(foreign_client);

  struct client *client = clientmgr_get_client(ctx, foreign_client->mac);

  if (!client) {
    printf("Didn't know about this client yet.\n");
    client = foreign_client;
    VECTOR_ADD(ctx->clients, *client);
  } else {
    printf("Merging clients\n");
    print_client(client);

    for (int i = 0; i < VECTOR_LEN(foreign_client->addresses); i++) {
      struct client_ip *e = &VECTOR_INDEX(foreign_client->addresses, i);
      struct client_ip *ip = clientmgr_get_client_ip(client, &e->address);

      printf("ip %p e %p\n", ip, e);

      if (ip == NULL) {
        VECTOR_ADD(client->addresses, *e);
      } else if (e->lastseen.tv_nsec > ip->lastseen.tv_nsec) {
        ip->lastseen = e->lastseen;
      }
    }
  }

  printf("Now I know about this client:\n");

  print_client(client);

  clientmgr_update_client_routes(l3ctx, ctx->export_table, client);
}

void clientmgr_handle_claim(clientmgr_ctx *ctx, struct l3ctx *l3ctx, uint32_t lastseen, uint8_t *mac, const struct in6_addr *sender) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);

  struct client *client = clientmgr_get_client(ctx, mac);

  printf("Received claim for %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  if (client == NULL)
    return;

  if (client->ours && client->lastseen.tv_sec > lastseen) {
    printf("Re-Claiming client\n");
    intercom_claim(&l3ctx->intercom_ctx, client->mac, now.tv_nsec - client->lastseen.tv_nsec);
  } else {
    printf("Dropping client\n");
    print_client(client);

    client->ours = false;
    intercom_info(&l3ctx->intercom_ctx, sender, client);

    clientmgr_remove_client_routes(l3ctx, ctx, client);
    clientmgr_delete_client(ctx, mac);
  }

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
    printf("  - %s (%ld.%.9ld)\n", str, e->lastseen.tv_sec, e->lastseen.tv_nsec);
  }
}
