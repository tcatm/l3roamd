#include "clientmgr.h"
#include "routemgr.h"
#include "icmp6.h"
#include "timespec.h"
#include "error.h"
#include "l3roamd.h"
#include "util.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* Static functions used only in this file. */
static bool client_is_active(const struct client *client);
static const char *state_str(enum ip_state state);

void mac_addr_n2a(char *mac_addr, unsigned char *arg) {
	int i, l;

	l = 0;
	for (i = 0; i < 6; i++) {
		if (i == 0) {
			sprintf(mac_addr+l, "%02x", arg[i]);
			l += 2;
		} else {
			sprintf(mac_addr+l, ":%02x", arg[i]);
			l += 3;
		}
	}
}


//struct in6_addr node_client_mcast_ip_from_mac(uint8_t mac[6]) {
//	char addr_str[INET6_ADDRSTRLEN];
//	snprintf(&addr_str[0], INET6_ADDRSTRLEN, "ff02::1:ff%02x:%02x%02x", mac[3], mac[4], mac[5]);
//}

struct in6_addr mac2ipv6(uint8_t mac[6], char * prefix) {
	struct in6_addr address = {};
	inet_pton(AF_INET6, prefix, &address);

	address.s6_addr[8] = mac[0] ^ 0x02;
	address.s6_addr[9] = mac[1];
	address.s6_addr[10] = mac[2];
	address.s6_addr[11] = 0xff;
	address.s6_addr[12] = 0xfe;
	address.s6_addr[13] = mac[3];
	address.s6_addr[14] = mac[4];
	address.s6_addr[15] = mac[5];

	return address;
}

bool prefix_contains(const struct prefix *prefix, struct in6_addr *addr) {
	int mask=0xff;
	for (int remaining_plen = prefix->plen, i=0;remaining_plen > 0; remaining_plen-= 8) {
		if (remaining_plen < 8)
			mask = 0xff & (0xff00 >>remaining_plen);

		if ((addr->s6_addr[i] & mask) != prefix->prefix.s6_addr[i])
			return false;
		i++;
	}
	return true;
}

void print_client(struct client *client) {
	char ifname[IFNAMSIZ];
	char mac_str[18];

	mac_addr_n2a(mac_str, client->mac);
	printf("Client %s", mac_str);

	if (client_is_active(client))
		printf(" (active");
	else
		printf(" (______");

	if (client->ifindex != 0) {
		if_indextoname(client->ifindex, ifname);
		printf(", %s/%i)\n", ifname, client->ifindex);
	} else {
		printf(")\n");
	}

	for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
		struct client_ip *addr = &VECTOR_INDEX(client->addresses, i);

		char str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &addr->addr, str, INET6_ADDRSTRLEN);

		switch (addr->state) {
			case IP_INACTIVE:
				printf("  %s  %s\n", state_str(addr->state), str);
				break;
			case IP_ACTIVE:
				printf("  %s    %s (%ld.%.9ld)\n", state_str(addr->state), str, addr->timestamp.tv_sec, addr->timestamp.tv_nsec);
				break;
			case IP_TENTATIVE:
				printf("  %s %s (tries left: %d)\n", state_str(addr->state), str, addr->tentative_retries_left);
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
	for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
		struct client_ip *ip = &VECTOR_INDEX(client->addresses, i);
		if (l3ctx.debug) {
			printf("looking at state %i for ip", ip->state);
			print_ip(&ip->addr, "\n");
		}

		if (ip->state == IP_ACTIVE || ip->state == IP_TENTATIVE)
			return true;
	}

	return false;
}

/** Adds the special node client IP address.
  */
void add_special_ip(clientmgr_ctx *ctx, struct client *client) {
	struct in6_addr address = mac2ipv6(client->mac, NODE_CLIENT_PREFIX);
	printf("Adding special address\n");
	rtnl_add_address(CTX(routemgr), &address);
}

/** Removes the special node client IP address.
  */
void remove_special_ip(clientmgr_ctx *ctx, struct client *client) {
	struct in6_addr address = mac2ipv6(client->mac, NODE_CLIENT_PREFIX);
	printf("Removing special address\n");
	rtnl_remove_address(CTX(routemgr), &address);
}

/** Given an IP address returns the client-object of a client.
    Returns NULL if no object is found.
    */
struct client_ip *get_client_ip(struct client *client, const struct in6_addr *address) {
	for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
		struct client_ip *e = &VECTOR_INDEX(client->addresses, i);

		if (memcmp(address, &e->addr, sizeof(struct in6_addr)) == 0)
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

		if (memcmp(address, &e->addr, sizeof(struct in6_addr)) == 0) {
			VECTOR_DELETE(client->addresses, i);
			break;
		}
	}

	char str[INET6_ADDRSTRLEN+1];
	inet_ntop(AF_INET6, address, str, INET6_ADDRSTRLEN);
	printf("\x1b[31mDeleted IP %s from client %zi addresses are still assigned\x1b[0m ", str, VECTOR_LEN(client->addresses));
	print_client(client);


	if (VECTOR_LEN(client->addresses) == 0) {
		printf("no IP-addresses left in client. Deleting client.\n");
		clientmgr_delete_client(&l3ctx.clientmgr_ctx, client->mac);
	}
}

/** Adds a route.
  */
void client_add_route(clientmgr_ctx *ctx, struct client *client, struct client_ip *ip) {
	routemgr_insert_neighbor(&l3ctx.routemgr_ctx, client->ifindex, &ip->addr , client->mac);
	printf("adding route for "); 
	print_ip(&ip->addr, "");
	if (clientmgr_is_ipv4(ctx, &ip->addr)) {
		printf(" (IPv4)\n");
		struct in_addr ip4 = {
			.s_addr = ip->addr.s6_addr[12] << 24 | ip->addr.s6_addr[13] << 16 | ip->addr.s6_addr[14] << 8 | ip->addr.s6_addr[15]
		};

		routemgr_insert_route(CTX(routemgr), ctx->export_table, ctx->nat46ifindex, &ip->addr, 128);
		routemgr_insert_route4(CTX(routemgr), ctx->export_table, client->ifindex, &ip4);
	} else {
		printf(" (IPv6)\n");
		routemgr_insert_route(CTX(routemgr), ctx->export_table, client->ifindex, &ip->addr, 128);
	}
}

/** Remove a route.
  */
void client_remove_route(clientmgr_ctx *ctx, struct client *client, struct client_ip *ip) {
	if (clientmgr_is_ipv4(ctx, &ip->addr)) {
		struct in_addr ip4 = {
			.s_addr = ip->addr.s6_addr[12] << 24 | ip->addr.s6_addr[13] << 16 | ip->addr.s6_addr[14] << 8 | ip->addr.s6_addr[15]
		};

		routemgr_remove_route(CTX(routemgr), ctx->export_table, &ip->addr, 128);
		routemgr_remove_route4(CTX(routemgr), ctx->export_table, &ip4);
		routemgr_remove_neighbor4(CTX(routemgr), client->ifindex, &ip4, client->mac);
	} else {
		routemgr_remove_route(CTX(routemgr), ctx->export_table, &ip->addr, 128);
		routemgr_remove_neighbor(CTX(routemgr), client->ifindex, &ip->addr, client->mac);
	}
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

/** Given an ip-address, this returns true if there is a local client connected having this IP-address and false otherwise
*/
bool clientmgr_is_known_address(clientmgr_ctx *ctx, struct in6_addr *address, struct client *client) {
	for (int i = 0; i < VECTOR_LEN(ctx->clients); i++) {
		struct client *c = &VECTOR_INDEX(ctx->clients, i);
		for (int j = 0; j< VECTOR_LEN(c->addresses);j++) {
			struct client_ip *a = &VECTOR_INDEX(c->addresses, j);
			if (l3ctx.debug) {
				printf("comparing ");
				print_ip(address, " and ");
				print_ip(&a->addr, "");
			}
			if (!memcmp(address, &a->addr, sizeof(struct in6_addr))) {
				if (l3ctx.debug) {
					char mac_str[18];
					mac_addr_n2a(mac_str, c->mac);
					printf(" => match found for client %s.\n", mac_str);
				}
				if (client)
					memcpy(client, c, sizeof(struct client));
				return true;
			}
		}
	}
	printf(" => no match found.\n");
	return false;
}

/** Get a client or create a new, empty one.
  */
struct client *get_or_create_client(clientmgr_ctx *ctx, const uint8_t mac[6], unsigned int ifindex) {
	struct client *client = get_client(ctx, mac);

	if (client == NULL) {
		struct client _client = {};
		memcpy(_client.mac, mac, sizeof(uint8_t) * 6);
		VECTOR_ADD(ctx->clients, _client);
		client = &VECTOR_INDEX(ctx->clients, VECTOR_LEN(ctx->clients) - 1);
		client->ifindex = ifindex;
	}

	return client;
}

/** Remove all client routes - used when exiting l3roamd
**/
void clientmgr_purge_clients(clientmgr_ctx *ctx) {
	struct client *client;

	for (int i=VECTOR_LEN(ctx->clients)-1;i>=0;i--) {
		client=&VECTOR_INDEX(ctx->clients, i);
		clientmgr_delete_client(ctx, client->mac);
	}
}

/** Given a MAC address deletes a client. Safe to call if the client is not
  known.
  */
void clientmgr_delete_client(clientmgr_ctx *ctx, uint8_t mac[6]) {
	struct client *client = get_client(ctx, mac);
	char mac_str[18];
	mac_addr_n2a(mac_str, mac);
	if (client == NULL) {
		if (l3ctx.debug) {
			printf("Client [%s] unknown: cannot delete\n", mac_str);
		}
		return;
	}



	printf("\033[34mREMOVING client %s and invalidating its IP-addresses\033[0m\n", mac_str);

	print_client(client);

	remove_special_ip(ctx, client);

	if (VECTOR_LEN(client->addresses) > 0) {
		for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
			struct client_ip *e = &VECTOR_INDEX(client->addresses, i);
			client_ip_set_state(CTX(clientmgr), client, e, IP_INACTIVE);
		}
	}
	VECTOR_FREE(client->addresses);

	// TODO: this is a rather low-level way of handling removal from the clients-vector. This could be improved by storing the index inside the client struct
	for (int i=0;i<VECTOR_LEN(ctx->clients);i++) {
		if (memcmp(client->mac, mac, sizeof(uint8_t)*6) == 0) {
			VECTOR_DELETE(ctx->clients, i);
		}
	}
}

const char *state_str(enum ip_state state) {
	switch (state) {
		case IP_INACTIVE:
			return "\x1b[31mINACTIVE\x1b[0m";
		case IP_ACTIVE:
			return "\x1b[32mACTIVE\x1b[0m";
		case IP_TENTATIVE:
			return "\x1b[33mTENTATIVE\x1b[0m";
		default:
			return "\x1b[35m(INVALID)\x1b[0m";
	}
}

/** Change state of an IP address. Trigger all side effects like resetting
    counters, timestamps and route changes.
  */
void client_ip_set_state(clientmgr_ctx *ctx, struct client *client, struct client_ip *ip, enum ip_state state) {
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	bool nop = false;

	switch (ip->state) {
		case IP_INACTIVE:
			switch (state) {
				case IP_INACTIVE:
					nop = true;
					break;
				case IP_ACTIVE:
					client_add_route(ctx, client, ip);
					ip->timestamp = now;
					break;
				case IP_TENTATIVE:
					ip->timestamp = now;
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
					nop = true;
					ip->timestamp = now;
					break;
				case IP_TENTATIVE:
					ip->timestamp = now;
					break;
			}
			break;
		case IP_TENTATIVE:
			switch (state) {
				case IP_INACTIVE:
					ip->timestamp = now;
					client_remove_route(ctx, client, ip);
					break;
				case IP_ACTIVE:
					ip->timestamp = now;
					client_add_route(ctx, client, ip);
					break;
				case IP_TENTATIVE:
					nop = true;
					ip->timestamp = now;
					break;
			}
			break;
	}

	if (!nop || l3ctx.debug) {
		print_ip(&ip->addr, "");
		printf(" changes from %s to %s\n", state_str(ip->state), state_str(state));
	}

	ip->state = state;
}

/** Check whether an IP address is contained in a client prefix.
  */
bool clientmgr_valid_address(clientmgr_ctx *ctx, struct in6_addr *address) {
	for (int i = 0; i < VECTOR_LEN(ctx->prefixes); i++) {
		struct prefix *_prefix = &VECTOR_INDEX(ctx->prefixes, i);
		if (prefix_contains(_prefix ,address))
			return true;
	}

	return clientmgr_is_ipv4(ctx, address);
}

/** Check whether an IP address is contained in the IPv4 prefix.
  */
bool clientmgr_is_ipv4(clientmgr_ctx *ctx, struct in6_addr *address) {
	return prefix_contains(&ctx->v4prefix, address);
}

/** Remove an address from a client identified by its MAC.
**/
void clientmgr_remove_address(clientmgr_ctx *ctx, struct client *client, struct in6_addr *address) {
	if (l3ctx.debug) {
		char str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, address, str, INET6_ADDRSTRLEN);
		char strmac[18];
		mac_addr_n2a(strmac, client->mac);
		printf("clientmgr_remove_address: %s is running for client %s",str, strmac);
	}

	if (client) {
		delete_client_ip(client, address);
	}

}

/** Add a new address to a client identified by its MAC.
 */
void clientmgr_add_address(clientmgr_ctx *ctx, struct in6_addr *address, uint8_t *mac, unsigned int ifindex) {

	if (!clientmgr_valid_address(ctx, address)) {
		if (l3ctx.debug)
			printf("address is not within a client-prefix, not adding.\n");
		return;
	}

	if (l3ctx.debug) {
		char mac_str[18];
		char ifname[IFNAMSIZ];
		char str[INET6_ADDRSTRLEN];

		if_indextoname(ifindex, ifname);
		mac_addr_n2a(mac_str, mac);
		inet_ntop(AF_INET6, address, str, INET6_ADDRSTRLEN);

		printf("clientmgr_add_address: %s[%s] is running for interface %i %s\n",str, mac_str, ifindex, ifname);
	}

	struct client *client = get_or_create_client(ctx, mac, ifindex);
	struct client_ip *ip = get_client_ip(client, address);
	client->ifindex = ifindex; // client might have roamed to different interface on the same node

	bool was_active = client_is_active(client);
	bool ip_is_new = ip == NULL;

	if (ip_is_new) {
		struct client_ip _ip = {};
		memcpy(&_ip.addr, address, sizeof(struct in6_addr));
		VECTOR_ADD(client->addresses, _ip);
		ip = &VECTOR_INDEX(client->addresses, VECTOR_LEN(client->addresses) - 1);
		client_ip_set_state(ctx, client, ip, IP_ACTIVE);
	}

	if (!was_active) {
		struct in6_addr address = mac2ipv6(client->mac, NODE_CLIENT_PREFIX);
		intercom_claim(CTX(intercom), &address, client);
	}

	if (ip_is_new)
		intercom_info(CTX(intercom), NULL, client, false);
}

/** Notify the client manager about a new MAC (e.g. a new wifi client).
  */
void clientmgr_notify_mac(clientmgr_ctx *ctx, uint8_t *mac, unsigned int ifindex) {
	struct client *client = get_or_create_client(ctx, mac, ifindex);

	if (client_is_active(client)) {
		if (l3ctx.debug) {
			char mac_str[18];
			mac_addr_n2a(mac_str, client->mac);
			printf("client[%s] was detected earlier, not re-adding\n", mac_str);
		}
		return;
	}


	char ifname[IFNAMSIZ];
	if_indextoname(ifindex, ifname);
	char mac_str[18];
	mac_addr_n2a(mac_str, client->mac);

	printf("\033[34mnew client %s on %s\033[0m\n", mac_str, ifname);

	// TODO It is rather nasty to hard-code the client-interface here. Still, all clients should appear on the client-interface, not anywhere else. Using the fdb detection mechanism, clients might end up appearing on the client bridge or somewhere else which should be prevented.
	// this means that we cannot support multiple client interfaces and that we absolutely need the client bridge.
	client->ifindex = ifindex;

	struct in6_addr address = mac2ipv6(client->mac, NODE_CLIENT_PREFIX);

	intercom_claim(CTX(intercom), &address, client);

	for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
		struct client_ip *ip = &VECTOR_INDEX(client->addresses, i);

		if (ip->state == IP_TENTATIVE || ip->state == IP_INACTIVE)
			client_ip_set_state(ctx, client, ip, IP_TENTATIVE);
	}

	// prefix does not matter here, icmp6_send_solicitation will overwrite the first 13 bytes of the address.
	icmp6_send_solicitation(CTX(icmp6), &address);
}

/** Handle claim (info request).
  */
void clientmgr_handle_claim(clientmgr_ctx *ctx, const struct in6_addr *sender, uint8_t mac[6]) {
	struct client *client = get_client(ctx, mac);

	if (client == NULL)
		return;

	bool active = client_is_active(client);

	intercom_info(CTX(intercom), sender, client, active);

//	if (active)
//		return;

	printf("Dropping client %02x:%02x:%02x:%02x:%02x:%02x in response to claim\n",  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	clientmgr_delete_client(ctx, mac);
}

/** Handle incoming client info.
  */
void clientmgr_handle_info(clientmgr_ctx *ctx, struct client *foreign_client, bool relinquished) {
	struct client *client = get_client(ctx, foreign_client->mac);
	if (l3ctx.debug) {
		printf("handling info message in clientmgr_handle_info() for foreign_client");
		print_client(foreign_client);
	}

	if (client == NULL || !client_is_active(client))
		return;

	for (int i = 0; i < VECTOR_LEN(foreign_client->addresses); i++) {
		struct client_ip *foreign_ip = &VECTOR_INDEX(foreign_client->addresses, i);
		struct client_ip *ip = get_client_ip(client, &foreign_ip->addr);

		// Skip if we know this IP address
		if (ip != NULL)
			continue;

		VECTOR_ADD(client->addresses, *foreign_ip);
		ip = &VECTOR_INDEX(client->addresses, VECTOR_LEN(client->addresses) - 1);

		client_ip_set_state(ctx, client, ip, IP_TENTATIVE);
	}

	if (relinquished)
		add_special_ip(ctx, client);

	printf("Client info merged ");
	print_client(client);
	printf("\n");
}

