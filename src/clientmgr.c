#include "clientmgr.h"
#include "routes.h"
#include "icmp6.h"
#include "timespec.h"
#include "error.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* Static functions used only in this file. */
static bool client_is_active(const struct client *client);
static void checkclient_task(void *d);
static void checkclient(clientmgr_ctx *ctx, uint8_t mac[6]);

bool prefix_contains(const struct prefix *prefix, struct in6_addr *addr) {
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

void print_client(struct client *client) {
  char ifname[IFNAMSIZ];

  printf("Client %02x:%02x:%02x:%02x:%02x:%02x", client->mac[0], client->mac[1],
                                                   client->mac[2], client->mac[3],
                                                   client->mac[4], client->mac[5]);

  if (client_is_active(client))
    puts(" (active)");
  else
    puts(" (------)");

  if (client->ifindex != 0) {
    if_indextoname(client->ifindex, ifname);
    printf("  Interface: %s (%i)\n", ifname, client->ifindex);
  }

  printf("  IP Adresses:\n");

  for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
    struct client_ip *e = &VECTOR_INDEX(client->addresses, i);

    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &e->address, str, INET6_ADDRSTRLEN);

    switch (e->state) {
      case IP_INACTIVE:
        printf("    - INACTIVE  %s\n", str);
        break;
      case IP_ACTIVE:
        printf("    - ACTIVE    %s (%ld.%.9ld)\n", str, e->timestamp.tv_sec, e->timestamp.tv_nsec);
        break;
      case IP_TENTATIVE:
        printf("    - TENTATIVE %s (tries left: %d)\n", str, e->tentative_cnt);
        break;
      default:
        exit_error("Invalid IP state");
    }
  }
}

/** Check whether a client is currently active.
    A client is considered active when at least one of its IP addresses is
    currently active or tentative.
    */
bool client_is_active(const struct client *client) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);

  if (timespec_cmp(client->timeout, now) > 0)
    return true;

  for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
    struct client_ip *ip = &VECTOR_INDEX(client->addresses, i);

    if (ip->state == IP_ACTIVE || ip->state == IP_TENTATIVE)
      return true;
  }

  return false;
}

/** Given an IP address returns the IP object of a client.
    Returns NULL if no object is found.
    */
struct client_ip *get_client_ip(struct client *client, const struct in6_addr *address) {
  for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
    struct client_ip *e = &VECTOR_INDEX(client->addresses, i);

    if (memcmp(address, &e->address, sizeof(struct in6_addr)) == 0)
      return e;
  }

  return NULL;
}

/** Removes an IP address from a client. Safe to call if the IP is not
    currently present in the clients list.
    */
void delete_client_ip(struct client *client, const struct in6_addr *address) {
  for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
    struct client_ip *e = &VECTOR_INDEX(client->addresses, i);

    if (memcmp(address, &e->address, sizeof(struct in6_addr)) == 0) {
      VECTOR_DELETE(client->addresses, i);
      break;
    }
  }
}

// TODO struct nach routes.c, remove_route noch table und ifindex mitgeben
// TODO refactor this

/** Adds a route.
  */
void client_add_route(clientmgr_ctx *ctx, struct client *client, struct client_ip *ip) {
  struct kernel_route route = {
    .plen = 128,
    .proto = 23,
    .ifindex = client->ifindex,
    .table = ctx->export_table
  };

  memcpy(route.prefix, ip->address.s6_addr, 16);

  insert_route(ctx->l3ctx, &route, client->mac);
}

/** Remove a route.
  */
void client_remove_route(clientmgr_ctx *ctx, struct client *client, struct client_ip *ip) {
  struct kernel_route route = {
    .plen = 128,
    .proto = 23,
    .table = ctx->export_table
  };

  memcpy(route.prefix, ip->address.s6_addr, 16);

  remove_route(ctx->l3ctx, &route);
}

/** Given a MAC address returns a client object.
    Returns NULL if the client is not known.
    */
struct client *get_client(clientmgr_ctx *ctx, const uint8_t mac[6]) {
  for (int i = 0; i < VECTOR_LEN(ctx->clients); i++) {
    struct client *e = &VECTOR_INDEX(ctx->clients, i);

    if (memcmp(mac, e->mac, sizeof(uint8_t) * 6) == 0)
      return e;
  }

  return NULL;
}

/** Get a client or create a new, empty one.
  */
struct client *get_or_create_client(clientmgr_ctx *ctx, const uint8_t mac[6]) {
  struct client *client = get_client(ctx, mac);

  if (client == NULL) {
    struct client _client = {};
    memcpy(_client.mac, mac, sizeof(uint8_t) * 6);
    VECTOR_ADD(ctx->clients, _client);
    client = &VECTOR_INDEX(ctx->clients, VECTOR_LEN(ctx->clients) - 1);
  }

  return client;
}

/** Given a MAC address deletes a client. Safe to call if the client is not
    known.
    */
void delete_client(clientmgr_ctx *ctx, const uint8_t mac[6]) {
  // TODO free addresses vector here?
  for (int i = 0; i < VECTOR_LEN(ctx->clients); i++) {
    struct client *e = &VECTOR_INDEX(ctx->clients, i);

    if (memcmp(mac, e->mac, sizeof(uint8_t) * 6) == 0) {
      VECTOR_DELETE(ctx->clients, i);
      break;
    }
  }
}

/** Change state of an IP address. Trigger all side effects like resetting
    counters, timestamps and route changes.
  */
void client_ip_set_state(clientmgr_ctx *ctx, struct client *client, struct client_ip *ip, enum ip_state state) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);

  switch (ip->state) {
    case IP_INACTIVE:
      switch (state) {
        case IP_INACTIVE:
          // ignore
          break;
        case IP_ACTIVE:
          client_add_route(ctx, client, ip);
          ip->timestamp = now;
          break;
        case IP_TENTATIVE:
          ip->timestamp = now;
          ip->tentative_cnt = TENTATIVE_TRIES;
          break;
      }
      break;
    case IP_ACTIVE:
      switch (state) {
        case IP_INACTIVE:
          ip->timestamp = now;
          client_remove_route(ctx, client, ip);
          break;
        case IP_ACTIVE:
          ip->timestamp = now;
          // TODO update route
          break;
        case IP_TENTATIVE:
          ip->timestamp = now;
          ip->tentative_cnt = TENTATIVE_TRIES;
          client_remove_route(ctx, client, ip);
          break;
      }
      break;
    case IP_TENTATIVE:
      switch (state) {
        case IP_INACTIVE:
          ip->timestamp = now;
          break;
        case IP_ACTIVE:
          ip->timestamp = now;
          client_add_route(ctx, client, ip);
          break;
        case IP_TENTATIVE:
          ip->timestamp = now;
          ip->tentative_cnt = TENTATIVE_TRIES;
          break;
      }
      break;
  }

  ip->state = state;
}

/** Schedule a client check. Set timeout to 0 in order to check the client at
    the next iteration.
    */
void schedule_clientcheck(clientmgr_ctx *ctx, struct client *client, unsigned int timeout) {
  struct client_task *data = calloc(1, sizeof(struct client_task));

  data->ctx = ctx;
  memcpy(data->mac, client->mac, 6);

  if (client->check_task == NULL)
    client->check_task = post_task(CTX(taskqueue), timeout, checkclient_task, data);
  else
    client->check_task = replace_task(CTX(taskqueue), client->check_task, timeout, checkclient_task, data);

  take_task(client->check_task);
}

/** Wrapper for checkclient to be used in post_task.
  */
void checkclient_task(void *d) {
  struct client_task *data = d;
  checkclient(data->ctx, data->mac);
}

/** Check a client.

    - Check timeout for active IP addresses (NA_TIMEOUT). Mark inactive if timed out.
    - Check timeout for inactive IP addresses (CLIENT_TIMEOUT). Remove if timed out.
    - Send NS for any tentative or active IP addresses.
    - Mark tentative IP addresses as inactive.
    - If the client has any IP addresses left re-schedule a check.
  */
void checkclient(clientmgr_ctx *ctx, uint8_t mac[6]) {
  struct client *client = get_client(ctx, mac);

  // The client may have vanished.
  if (client == NULL)
    return;

  printf("Checking on client\n");
  print_client(client);

  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);

  struct timespec na_timeout = now;
  struct timespec client_timeout = now;

  na_timeout.tv_sec -= NA_TIMEOUT;
  client_timeout.tv_sec -= CLIENT_TIMEOUT;

  for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
    struct client_ip *ip = &VECTOR_INDEX(client->addresses, i);

    switch (ip->state) {
      case IP_ACTIVE:
        if (timespec_cmp(ip->timestamp, na_timeout) <= 0)
          client_ip_set_state(ctx, client, ip, IP_INACTIVE);
        icmp6_send_solicitation(CTX(icmp6), &ip->address);
        break;
      case IP_INACTIVE:
        if (timespec_cmp(ip->timestamp, client_timeout) <= 0) {
          VECTOR_DELETE(client->addresses, i);
          i--;
        }
        break;
      case IP_TENTATIVE:
        icmp6_send_solicitation(CTX(icmp6), &ip->address);
        ip->tentative_cnt--;
        if (ip->tentative_cnt <= 0)
          client_ip_set_state(ctx, client, ip, IP_INACTIVE);
        break;
    }
  }

  // If the client has no IP addresses associated and has timed out (after a
  // roaming event), delete it.
  if (VECTOR_LEN(client->addresses) == 0 && timespec_cmp(client->timeout, now) <= 0) {
    delete_client(ctx, client->mac);
    return;
  }

  // TODO schedule at earliest IP timeout
  schedule_clientcheck(ctx, client, IP_CHECKCLIENT_TIMEOUT);
}

/** Add a new address to a client identified by its MAC.
 */
void clientmgr_add_address(clientmgr_ctx *ctx, struct in6_addr *address, uint8_t *mac, unsigned int ifindex) {
  // TODO sicherstellen, dass IPs nur jeweils einem Client zugeordnet sind

  char str[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, address, str, INET6_ADDRSTRLEN);
  printf("Add Address: %s\n", str);

  if (!prefix_contains(&ctx->prefix, address))
    return;

  struct client *client = get_or_create_client(ctx, mac);
  struct client_ip *ip = get_client_ip(client, address);

  bool was_active = client_is_active(client);
  bool ip_is_new = ip == NULL;

  if (ip == NULL) {
    struct client_ip _ip = {};
    memcpy(&_ip.address, address, sizeof(struct in6_addr));
    VECTOR_ADD(client->addresses, _ip);
    ip = &VECTOR_INDEX(client->addresses, VECTOR_LEN(client->addresses) - 1);
  }

  client->ifindex = ifindex;

  client_ip_set_state(ctx, client, ip, IP_ACTIVE);

  if (!was_active)
    intercom_claim(CTX(intercom), client);

  // If the IP address is new, add to distributed database (neighbor's for now).
  if (ip_is_new)
    intercom_info(CTX(intercom), NULL, client);

  schedule_clientcheck(ctx, client, IP_CHECKCLIENT_TIMEOUT);

  print_client(client);
}

/** Notify the client manager about a new MAC (e.g. a new wifi client).
  */
void clientmgr_notify_mac(clientmgr_ctx *ctx, uint8_t *mac, unsigned int ifindex) {
  struct client *client = get_or_create_client(ctx, mac);

  char ifname[IFNAMSIZ];
  if_indextoname(ifindex, ifname);

  printf("\033[34mnew client %02x:%02x:%02x:%02x:%02x:%02x on %s\033[0m\n",
         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ifname);

  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);

  client->timeout = now;
  client->timeout.tv_sec += CLIENT_TIMEOUT;
  client->ifindex = ifindex;

  intercom_claim(CTX(intercom), client);

  // Mark all inactive IP addresses tentative and schedule a check to establish
  // whether the client is using them now.
  for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
    struct client_ip *ip = &VECTOR_INDEX(client->addresses, i);

    if (ip->state == IP_TENTATIVE || ip->state == IP_INACTIVE)
      client_ip_set_state(ctx, client, ip, IP_TENTATIVE);
  }

  schedule_clientcheck(ctx, client, 0);
}

/** Handle info request.
  */
void clientmgr_handle_claim(clientmgr_ctx *ctx, const struct in6_addr *sender, uint8_t mac[6]) {
  struct client *client = get_client(ctx, mac);

  if (client == NULL)
    return;

  intercom_info(CTX(intercom), sender, client);

  if (!client_is_active(client))
    return;

  printf("Dropping client in response to claim\n");
  print_client(client);

  for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
    struct client_ip *ip = &VECTOR_INDEX(client->addresses, i);

    if (ip->state == IP_ACTIVE || ip->state == IP_TENTATIVE)
      client_ip_set_state(ctx, client, ip, IP_TENTATIVE);
  }

  schedule_clientcheck(ctx, client, 0);
}

/** Handle incoming client info.
  */
void clientmgr_handle_info(clientmgr_ctx *ctx, struct client *foreign_client) {
  printf("Received client info\n");
  print_client(foreign_client);

  struct client *client = get_client(ctx, foreign_client->mac);

  if (client == NULL || !client_is_active(client))
    return;

  for (int i = 0; i < VECTOR_LEN(foreign_client->addresses); i++) {
    struct client_ip *foreign_ip = &VECTOR_INDEX(foreign_client->addresses, i);
    struct client_ip *ip = get_client_ip(client, &foreign_ip->address);

    // Skip if we know this IP address
    if (ip != NULL)
      continue;

    VECTOR_ADD(client->addresses, *foreign_ip);
    ip = &VECTOR_INDEX(client->addresses, VECTOR_LEN(client->addresses) - 1);

    client_ip_set_state(ctx, client, ip, IP_TENTATIVE);
  }

  printf("Merged client\n");

  print_client(client);

  schedule_clientcheck(ctx, client, 0);
}
