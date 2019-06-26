/*
 * This file is part of project l3roamd. It's copyrighted by the contributors
 * recorded in the version control history of the file, available from
 * its original location https://github.com/freifunk-gluon/l3roamd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "intercom.h"
#include "alloc.h"
#include "error.h"
#include "icmp6.h"
#include "if.h"
#include "l3roamd.h"
#include "prefix.h"
#include "syscallwrappers.h"
#include "util.h"

#include "clientmgr.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define INTERCOM_GROUP "ff02::5523"
#define INTERCOM_MAX_RECENT 100

void schedule_retries(struct intercom_task *data, int ms_timeout, void (*processor)(void *data));

bool join_mcast(const struct in6_addr addr, intercom_if_t *iface) {
	struct ipv6_mreq mreq;

	mreq.ipv6mr_multiaddr = addr;
	mreq.ipv6mr_interface = iface->ifindex;

	if (mreq.ipv6mr_interface == 0)
		goto error;

	if (setsockopt(iface->mcast_recv_fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == 0)
		return true;
	else if (errno == EADDRINUSE)
		return true;

error:
	log_error("Could not join multicast group on %s: ", iface->ifname);
	perror(NULL);
	return false;
}

bool leave_mcast(const struct in6_addr addr, intercom_if_t *iface) {
	struct ipv6_mreq mreq;

	mreq.ipv6mr_multiaddr = addr;
	mreq.ipv6mr_interface = iface->ifindex;

	if (mreq.ipv6mr_interface == 0)
		goto error;

	if (setsockopt(iface->mcast_recv_fd, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mreq, sizeof(mreq)) == 0)
		return true;

error:
	log_error("Could not leave multicast group on %s: ", iface->ifname);
	perror(NULL);
	return false;
}


void free_intercom_task(void *d) {
	struct intercom_task *data = d;
	free(data->packet);
	free(data->client);
	free(data->recipient);
	free(data);
}

void intercom_update_interfaces(intercom_ctx *ctx) {
	for (int i = 0; i < VECTOR_LEN(ctx->interfaces); i++) {
		intercom_if_t *iface = &VECTOR_INDEX(ctx->interfaces, i);

		iface->ifindex = if_nametoindex(iface->ifname);

		if (!iface->ifindex)
			continue;

		iface->ok = join_mcast(ctx->groupaddr.sin6_addr, iface);
	}
}

int intercomif_compare_by_name(const struct intercom_if *a, const struct intercom_if *b) {
	return strncmp(a->ifname, b->ifname, IFNAMSIZ);
}

intercom_if_t *intercom_has_ifname(intercom_ctx *ctx, const char *ifname, int *elementindex) {
	intercom_if_v vec = *(intercom_if_v *)&ctx->interfaces;

	struct intercom_if key = {};
	key.ifname = strdupa(ifname);

	struct intercom_if *ret = (struct intercom_if *)VECTOR_LSEARCH(&key, vec, intercomif_compare_by_name);

	if (ret) {
		log_debug("match on interface-vector for %s", ifname);

		if (ret != NULL && elementindex != NULL) {
			*elementindex = ((void *)ret - (void *)&VECTOR_INDEX(vec, 0)) / sizeof(intercom_if_t);
			log_debug(" on index %i", *elementindex);
		}
		log_debug("\n");
	}

	return ret;
}

bool intercom_add_interface(intercom_ctx *ctx, char *ifname) {
	if (!ifname || intercom_has_ifname(ctx, ifname, NULL))
		return false;

	int ifindex = if_nametoindex(ifname);

	if (ifindex == 0) {
		fprintf(stderr, "ignoring unknown mesh-interface %s\n", ifname);
		return false;
	}

	log_verbose("adding mesh interface %s\n", ifname);

	intercom_if_t iface = {.ok = false, .ifname = ifname, .ifindex = ifindex};

	int fd = socket(PF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (fd < 0)
		exit_error("creating socket");

	ctx->groupaddr.sin6_scope_id = ifindex;
	if (bind(fd, (struct sockaddr *)&ctx->groupaddr, sizeof(ctx->groupaddr)) < 0) {
		perror("bind to multicast-address failed");
		exit(EXIT_FAILURE);
	}

	iface.mcast_recv_fd = fd;
	log_debug("ASSIGNING fd: %i to mcast_recv_fd on interface %s\n", fd, ifname);

	VECTOR_ADD(ctx->interfaces, iface);
	intercom_update_interfaces(&l3ctx.intercom_ctx);

	return true;
}

bool intercom_del_interface(intercom_ctx *ctx, char *ifname) {
	int elementindex;
	intercom_if_t *meshif = intercom_has_ifname(ctx, ifname, &elementindex);

	if (!meshif)
		return false;

	log_verbose("removing mesh interface %s\n", ifname);

	leave_mcast(ctx->groupaddr.sin6_addr, meshif);

	close(meshif->mcast_recv_fd);

	free(meshif->ifname);

	VECTOR_DELETE(ctx->interfaces, elementindex);
	return true;
}

void obtainll(const char *ifname, struct in6_addr *ret) {
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in6 *sa;
	struct in6_addr ll = {};

	inet_pton(AF_INET6, "fe80::", &ll);

	getifaddrs(&ifap);
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET6) {
			if (!memcmp(ifname, ifa->ifa_name, strlen(ifname))) {
				sa = (struct sockaddr_in6 *)ifa->ifa_addr;
				struct prefix p = {.plen = 64, .prefix = ll};
				if (prefix_contains(&p, &sa->sin6_addr)) {
					memcpy(ret, &sa->sin6_addr, sizeof(struct in6_addr));
					goto end;
				}
			}
		}
	}

end:
	freeifaddrs(ifap);
}

void intercom_init_unicast(intercom_ctx *ctx) {
	struct sockaddr_in6 server_addr = {
	    .sin6_family = AF_INET6, .sin6_port = htons(INTERCOM_PORT),
	};

	ctx->unicast_nodeip_fd = socket(PF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (ctx->unicast_nodeip_fd < 0)
		exit_error("creating socket for intercom on node-IP");

	memcpy(&server_addr.sin6_addr, ctx->ip.s6_addr, 16);
	if (bind(ctx->unicast_nodeip_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("bind socket to node-IP failed");
		exit(EXIT_FAILURE);
	}

	log_verbose("ASSIGNING fd: %i to unicast_nodeip_fd\n", ctx->unicast_nodeip_fd);
}

void intercom_init(intercom_ctx *ctx) {
	struct in6_addr mgroup_addr;
	if (inet_pton(AF_INET6, INTERCOM_GROUP, &mgroup_addr) < 1) {
		exit_errno(
		    "Could not convert intercom-group to network "
		    "representation");
	};

	ctx->groupaddr = (struct sockaddr_in6){
	    .sin6_family = AF_INET6, .sin6_addr = mgroup_addr, .sin6_port = htons(INTERCOM_PORT),
	};

	intercom_update_interfaces(ctx);
}

int assemble_header(intercom_packet_hdr *hdr, uint8_t ttl, uint8_t type) {
	uint32_t nonce;
	hdr->type = type;
	hdr->version = L3ROAMD_PACKET_FORMAT_VERSION;
	hdr->ttl = ttl;
	hdr->empty = 0;
	obtainrandom(&nonce, sizeof(uint32_t), 0);
	hdr->nonce = htonl(nonce);
	memcpy(&hdr->sender, &l3ctx.intercom_ctx.ip, 16);

	return sizeof(intercom_packet_hdr);
}

int assemble_seek_address(uint8_t *packet, const struct in6_addr *address) {
	packet[0] = SEEK_ADDRESS;
	packet[1] = 20;
	packet[2] = packet[3] = 0;
	memcpy(&packet[4], address, 16);

	return packet[1];
}

int assemble_macinfo(uint8_t *packet, uint8_t *mac, uint8_t type) {
	packet[0] = type;
	packet[1] = 8;
	memcpy(&packet[2], mac, 6);
	return packet[1];
}

uint8_t assemble_platinfo(uint8_t *packet) {
	uint16_t lease = htons(0);
	packet[0] = INFO_PLAT;
	packet[1] = 20;
	memcpy(&packet[2], &lease, 2);
	memcpy(&packet[4], &l3ctx.clientmgr_ctx.platprefix, 16);
	return packet[1];
}

uint8_t assemble_basicinfo(uint8_t *packet, struct client *client) {
	uint8_t num_addresses = 0;

	packet[0] = INFO_BASIC;
	memcpy(&packet[2], client->mac, 6);

	intercom_packet_info_entry *entry =
	    (intercom_packet_info_entry *)((uint8_t *)(packet) + sizeof(client->mac) + 2);

	for (int i = 0; i < VECTOR_LEN(client->addresses) && num_addresses < INFO_MAX; i++) {
		struct client_ip *ip = &VECTOR_INDEX(client->addresses, i);
		if (ip_is_active(ip)) {
			memcpy(&entry->address, ip->addr.s6_addr, sizeof(uint8_t) * 16);
			entry++;
			num_addresses++;
		}
	}

	log_debug("added %i addresses to info packet for client \n%s\n", num_addresses, print_client(client));

	// fill length field
	packet[1] = num_addresses * sizeof(intercom_packet_info_entry) + sizeof(client->mac) + 2;
	return packet[1];
}

void intercom_seek(intercom_ctx *ctx, const struct in6_addr *address) {
	intercom_packet_seek *packet = l3roamd_alloc(sizeof(intercom_packet_seek) + 20);

	int offset = assemble_header(&packet->hdr, 255, INTERCOM_SEEK);
	offset += assemble_seek_address((void *)packet + offset, address);

	intercom_recently_seen_add(ctx, &packet->hdr);

	intercom_send_packet(ctx, (uint8_t *)packet, offset);
	free(packet);
}

bool intercom_send_packet_unicast(intercom_ctx *ctx, const struct in6_addr *recipient, uint8_t *packet,
				  ssize_t packet_len) {
	struct sockaddr_in6 addr =
	    (struct sockaddr_in6){.sin6_family = AF_INET6, .sin6_port = htons(INTERCOM_PORT), .sin6_addr = *recipient};

	// when sending unicast packets, always set ttl to 1 to avoid re-transmits to
	// self on the receiver
	((intercom_packet_info *)packet)->hdr.ttl = 1;

	// log_debug("fd: %i, packet %p, length: %zi\n", ctx->unicast_nodeip_fd, packet, packet_len);

	ssize_t rc = sendto(ctx->unicast_nodeip_fd, packet, packet_len, 0, (struct sockaddr *)&addr, sizeof(addr));
	log_debug("sent intercom packet rc: %zi to %s\n", rc, print_ip(recipient));

	if (rc < 0)
		perror(
		    "sendto failed (if this was a claim and there is a "
		    ">Permission denied< then this is ok, the client is new to "
		    "the network)");  // How could we catch this better?

	return rc >= 0;
}

void intercom_send_packet(intercom_ctx *ctx, uint8_t *packet, ssize_t packet_len) {
	for (int i = 0; i < VECTOR_LEN(ctx->interfaces); i++) {
		intercom_if_t *iface = &VECTOR_INDEX(ctx->interfaces, i);
		int fd = ctx->unicast_nodeip_fd;

		if (!iface->ok)
			continue;

		struct sockaddr_in6 _groupaddr = {};
		memcpy(&_groupaddr, &ctx->groupaddr, sizeof(struct sockaddr_in6));

		_groupaddr.sin6_scope_id = iface->ifindex;

		ssize_t rc =
		    sendto(fd, packet, packet_len, 0, (struct sockaddr *)&_groupaddr, sizeof(struct sockaddr_in6));
		log_debug("sent intercom packet to %s on iface %s rc: %zi\n", print_ip(&_groupaddr.sin6_addr),
			  iface->ifname, rc);
		if (rc < 0)
			iface->ok = false;
	}
}

bool intercom_recently_seen(intercom_ctx *ctx, intercom_packet_hdr *hdr) {
	for (int i = 0; i < VECTOR_LEN(ctx->recent_packets); i++) {
		intercom_packet_hdr *ref_hdr = &VECTOR_INDEX(ctx->recent_packets, i);

		if (ref_hdr->nonce == hdr->nonce && ref_hdr->type == hdr->type)
			return true;
	}
	return false;
}

void intercom_recently_seen_add(intercom_ctx *ctx, intercom_packet_hdr *hdr) {
	while (VECTOR_LEN(ctx->recent_packets) > INTERCOM_MAX_RECENT) VECTOR_DELETE(ctx->recent_packets, 0);

	VECTOR_ADD(ctx->recent_packets, *hdr);
}

int parse_address(const uint8_t *packet, struct in6_addr *address) {
	log_debug("parsing seek packet segment: address\n");
	memcpy(address, &packet[4], 16);
	return packet[1];
}

int parse_mac(const uint8_t *packet, mac *claim) {
	log_debug("parsing packet segment: mac\n");
	memcpy(claim->mac, &packet[2], 6);
	return packet[1];
}

int parse_plat(const uint8_t *packet, struct client *client) {
	log_debug("parsing info packet plat\n");
	memcpy(&l3ctx.clientmgr_ctx.platprefix, &packet[4], 16);
	return packet[1];
}

int parse_basic(const uint8_t *packet, struct client *client) {
	memcpy(client->mac, &packet[2], sizeof(uint8_t) * 6);
	uint8_t length = packet[1];
	int num_addresses = (length - 2 - 6) / 16;

	log_debug("handling info segment with %i addresses for client %s\n", num_addresses, print_client(client));

	struct client_ip ip = {};
	ip.state = IP_INACTIVE;

	intercom_packet_info_entry *entry = (intercom_packet_info_entry *)(packet + 8);

	for (int i = 0; i < num_addresses; i++) {
		memcpy(&ip.addr.s6_addr, &entry->address, sizeof(uint8_t) * 16);
		VECTOR_ADD(client->addresses, ip);
		log_debug("%s learnt from info packet\n", print_ip(&ip.addr));
		entry++;
	}

	return length;
}

// handler returns true if packet should be forwarded
bool intercom_handle_seek(intercom_ctx *ctx, intercom_packet_seek *packet, int packet_len) {
	struct in6_addr address = {};
	int currentoffset = sizeof(intercom_packet_info);
	uint8_t *packetpointer;
	uint8_t type;

	while (currentoffset < packet_len) {
		packetpointer = &((uint8_t *)packet)[currentoffset];
		type = *packetpointer;
		log_debug("offset: %i %p %p\n", currentoffset, packet, packetpointer);
		switch (type) {
			case SEEK_ADDRESS:
				currentoffset += parse_address(packetpointer, &address);

				printf("\x1b[36mSEEK: Looking for %s\x1b[0m\n", print_ip(&address));

				if (address_is_ipv4(&address))
					arp_send_request(&l3ctx.arp_ctx, &address);
				else
					icmp6_send_solicitation(&l3ctx.icmp6_ctx, &address);
				break;
			default:
				log_error(
				    "unknown segment of type %i found in info "
				    "packet. ignoring this piece\n",
				    type);
				break;
		}
	}
	return true;
}

bool intercom_handle_claim(intercom_ctx *ctx, intercom_packet_claim *packet, int packet_len) {
	struct in6_addr sender;
	int currentoffset = sizeof(intercom_packet_info);
	uint8_t *packetpointer;
	uint8_t type;

	mac claim = {};
	memcpy(&sender.s6_addr, &packet->hdr.sender, sizeof(uint8_t) * 16);

	if (!memcmp(sender.s6_addr, ctx->ip.s6_addr, 16)) {
		log_verbose("discarding claim from own node\n");
		return false;  // this makes the assumption that this packet was
			       // unicast. Claims should be unicast.
	}

	log_verbose("handling claim from: %s\n", print_ip(&sender));

	while (currentoffset < packet_len) {
		packetpointer = &((uint8_t *)packet)[currentoffset];
		type = *packetpointer;
		log_debug("offset: %i %p %p\n", currentoffset, packet, packetpointer);
		switch (type) {
			case CLAIM_MAC:
				currentoffset += parse_mac(packetpointer, &claim);
				break;
			default:
				log_error(
				    "unknown segment of type %i found in info "
				    "packet. ignoring this piece\n",
				    type);
				break;
		}
	}

	return !clientmgr_handle_claim(&l3ctx.clientmgr_ctx, &sender, claim.mac);
}

/* find an entry in a vector containing elements of type client_t */
struct client *find_repeatable(void *v, client_t *k, int *elementindex) {
	client_v vec = *(client_v *)v;

	client_t key = {};
	memcpy(key.mac, k->mac, ETH_ALEN);

	// TODO: replace this with VECTOR_BSEARCH
	struct client *ret = (struct client *)VECTOR_LSEARCH(&key, vec, client_compare_by_mac);

	if (ret != NULL) {
		log_debug("match on vector for mac %s", print_mac(k->mac));

		if (elementindex != NULL) {
			*elementindex = VECTOR_GETINDEX(vec, ret);
			log_debug(" on index %i", *elementindex);
		}
		log_debug("\n");
	}

	return ret;
}

void intercom_remove_claim(intercom_ctx *ctx, struct client *client ) {
	int i = -1;
	if (find_repeatable(&ctx->repeatable_claims, client, &i))
		VECTOR_DELETE(ctx->repeatable_claims, i);
}

bool intercom_handle_ack(intercom_ctx *ctx, intercom_packet_ack *packet, int packet_len) {
	mac client_mac = {};
	uint8_t type, *packetpointer;
	int currentoffset = sizeof(intercom_packet_info);

	while (currentoffset < packet_len) {
		packetpointer = &((uint8_t *)packet)[currentoffset];
		type = *packetpointer;
		log_debug("offset: %i packet starts at: %p, packetpointer: %p\n", currentoffset, packet, packetpointer);
		switch (type) {
			case ACK_MAC:
				currentoffset += parse_mac((uint8_t *)packetpointer, &client_mac);
				break;
			default:
				log_error(
				    "unknown segment of type %i found in ack "
				    "packet. ignoring this piece\n",
				    type);
				break;
		}
	}

	log_verbose("handling ACK packet for Client with mac %s\n", print_mac(client_mac.mac));

	int i = 0;
	client_t c = {};
	memcpy(c.mac, client_mac.mac, ETH_ALEN);

	if (find_repeatable(&ctx->repeatable_infos, &c, &i))
		VECTOR_DELETE(ctx->repeatable_infos, i);

	return false;  // never forward acks
}

bool intercom_handle_info(intercom_ctx *ctx, intercom_packet_info *packet, int packet_len) {
	uint8_t type, *packetpointer;
	struct client client = {};
	int currentoffset = sizeof(intercom_packet_info);
	struct in6_addr sender;

	memcpy(&sender.s6_addr, &packet->hdr.sender, sizeof(uint8_t) * 16);

	log_debug("parsing info packet with length %i from: %s\n", packet_len, print_ip(&sender));

	while (currentoffset < packet_len) {
		packetpointer = &((uint8_t *)packet)[currentoffset];
		type = *packetpointer;
		log_debug("offset: %i %p %p\n", currentoffset, packet, packetpointer);
		switch (type) {
			case INFO_PLAT:
				currentoffset += parse_plat(packetpointer, &client);
				break;
			case INFO_BASIC:
				currentoffset += parse_basic(packetpointer, &client);
				break;
			default:
				log_error(
				    "unknown segment of type %i found in info "
				    "packet. ignoring this piece\n",
				    type);
				break;
		}
	}

	intercom_remove_claim(ctx, &client);

	bool acted_on_local_client = clientmgr_handle_info(&l3ctx.clientmgr_ctx, &client);
	intercom_ack(ctx, &sender, &client);
	VECTOR_FREE(client.addresses);
	return !acted_on_local_client;
}

void intercom_handle_packet(intercom_ctx *ctx, uint8_t *packet, ssize_t packet_len) {
	intercom_packet_hdr *hdr = (intercom_packet_hdr *)packet;
	bool forward = true;

	if (hdr->version == L3ROAMD_PACKET_FORMAT_VERSION) {
		if (intercom_recently_seen(ctx, hdr))
			return;

		intercom_recently_seen_add(ctx, hdr);
		if (hdr->type == INTERCOM_SEEK)
			forward = intercom_handle_seek(ctx, (intercom_packet_seek *)packet, packet_len);

		if (hdr->type == INTERCOM_CLAIM)
			forward = intercom_handle_claim(ctx, (intercom_packet_claim *)packet, packet_len);

		if (hdr->type == INTERCOM_INFO)
			forward = intercom_handle_info(ctx, (intercom_packet_info *)packet, packet_len);

		if (hdr->type == INTERCOM_ACK)
			forward = intercom_handle_ack(ctx, (intercom_packet_ack *)packet, packet_len);

		hdr->ttl--;
		if (hdr->ttl > 0 && forward)
			intercom_send_packet(ctx, packet, packet_len);
	} else {
		// if the packet version is unknown we cannot decrement ttl
		// because we do not know where it is in the packet. Also the
		// check whether we have already seen it fails.
		// all we can do is self-preservation and not crash and forward.
		// However if we forward while having no already_seen_checks we
		// will break the network. => dropping the packet.
		log_error(
		    "unknown packet with version %i received on intercom. "
		    "Ignoring content and dropping the packet that could have "
		    "originated from: %s or %s. This is a guess with current "
		    "or previous positions of the originator\n",
		    hdr->version, print_ip((void *)&packet[6]), print_ip((void *)hdr->sender));
	}
}

void intercom_handle_in(intercom_ctx *ctx, int fd) {
	ssize_t count;
	uint8_t buf[ctx->mtu];

	log_debug("HANDLING INTERCOM PACKET on fd %i using buffersize of %i ", fd, ctx->mtu);

	while (1) {
		count = read(fd, buf, ctx->mtu);
		log_debug("- read %zi Bytes of data\n", count);
		if (count == -1) {
			/* If errno == EAGAIN, that means we have read all
			   data. So go back to the main loop.
			   if the last intercom packet was a claim for a local
			   client, then we have just dropped the local client
			   and will receive EBADF on the fd for the
			   node-client-IP. This is not an error.*/
			if (errno == EBADF) {
				perror(
				    "read error - if we just dropped a local "
				    "client due to this intercom packet being "
				    "a claim then this is all right. otherwise "
				    "there is something crazy going on. - "
				    "returning to the main loop");
				printf("the EBADF happened on fd: %i\n", fd);
			} else if (errno != EAGAIN) {
				perror(
				    "read error - this should not happen - "
				    "going back to main loop");
			}
			break;
		} else if (count == 0) {
			/* End of file. The remote has closed the
			   connection. */
			break;
		}

		// TODO if this is a claim for a local client, we should just
		// stop iterating and get rid of the EBADF check above
		intercom_handle_packet(ctx, buf, count);
	}
}

void info_retry_task(void *d) {
	struct intercom_task *data = d;

	int repeatable_info_index;
	if (!find_repeatable(&l3ctx.intercom_ctx.repeatable_infos, data->client, &repeatable_info_index))
		return;

	if (data->recipient != NULL) {
		log_debug("sending unicast info with length %i for client %s to %s\n", data->packet_len,
			  print_mac(data->client->mac), print_ip(data->recipient));
		intercom_send_packet_unicast(&l3ctx.intercom_ctx, data->recipient, (uint8_t *)(data->packet),
					     data->packet_len);
	} else {
		// forward packet to other l3roamd instances
		log_debug("sending info for client %s to l3roamd neighbours\n", print_mac(data->client->mac));
		intercom_recently_seen_add(&l3ctx.intercom_ctx, &((intercom_packet_info *)data->packet)->hdr);
		intercom_send_packet(&l3ctx.intercom_ctx, data->packet, data->packet_len);
	}

	if (data->retries_left > 0)
		schedule_retries(data, 500, info_retry_task);
	else {
		// we have not received an ACK message, otherwise we would not
		// have run out of retries => likely packet loss. At some point
		// in time, retries need to stop.
		VECTOR_DELETE(l3ctx.intercom_ctx.repeatable_infos, repeatable_info_index);
	}
}

bool intercom_info(intercom_ctx *ctx, const struct in6_addr *recipient, struct client *client, bool relinquished) {
	int i;
	if (find_repeatable(&ctx->repeatable_infos, client, &i))
		return true;
	else
		log_debug("Assembling INFO for client [%s]\n", print_mac(client->mac));

	struct intercom_task *data = l3roamd_alloc(sizeof(struct intercom_task));
	data->packet = l3roamd_alloc(sizeof(intercom_packet_info) + sizeof(intercom_packet_info_plat) +
				     (8 + INFO_MAX * sizeof(intercom_packet_info_entry)));

	data->packet_len = assemble_header(&((intercom_packet_info *)data->packet)->hdr, 255, INTERCOM_INFO);

	data->packet_len += assemble_platinfo(data->packet + data->packet_len);
	data->packet_len += assemble_basicinfo(data->packet + data->packet_len, client);

	// log_debug("current offset: %i\n", data->packet_len);

	VECTOR_ADD(ctx->repeatable_infos, *client);

	data->client = l3roamd_alloc(sizeof(struct client));
	memcpy(data->client, client, sizeof(struct client));
	data->retries_left = INFO_RETRY_MAX;
	data->check_task = NULL;
	data->recipient = NULL;

	if (recipient) {
		data->recipient = l3roamd_alloc_aligned(sizeof(struct in6_addr), 16);
		memcpy(data->recipient, recipient, sizeof(struct in6_addr));
		((intercom_packet_info *)data->packet)->hdr.ttl = 1;
	}

	data->check_task = post_task(&l3ctx.taskqueue_ctx, 0, 0, info_retry_task, free_intercom_task, data);
	return true;
}

void claim_retry_task(void *d) {
	struct intercom_task *data = d;
	bool unicast_packet_sent = true;

	int repeatable_claim_index;
	if (!find_repeatable(&l3ctx.intercom_ctx.repeatable_claims, data->client, &repeatable_claim_index)) {
		log_debug(
		    "could not find repeatable claim for client [%s]. This happens when an INFO packet was received "
		    "before all claim retry-cycles are spent OR when deleting the client. Returning.\n",
		    print_mac(data->client->mac));
		return;
	}

	if (data->recipient != NULL) {
		log_debug("sending unicast claim for client %s to %s\n", print_mac(data->client->mac),
			  print_ip(data->recipient));
		unicast_packet_sent = intercom_send_packet_unicast(&l3ctx.intercom_ctx, data->recipient,
								   (uint8_t *)data->packet, data->packet_len);
	} else {
		log_debug("sending multicast claim for client %s\n", print_mac(data->client->mac));
		intercom_recently_seen_add(&l3ctx.intercom_ctx, &((intercom_packet_claim *)data->packet)->hdr);
		intercom_send_packet(&l3ctx.intercom_ctx, (uint8_t *)&data->packet, data->packet_len);
	}

	if (data->retries_left > 0 && unicast_packet_sent)
		schedule_retries(data, 300, claim_retry_task);
	else {
		// we have not received an info message or sending a unicast
		// claim was not successful
		// the only valid reason for this to happen is when
		// there is no route to the client, so it must be new to the
		// network
		// TODO: what about EINTR EWOULDBLOCK ENOBUFS ENOMEM
		// => noone knew the client and it is new to the mesh.
		// => adding the special IP
		VECTOR_DELETE(l3ctx.intercom_ctx.repeatable_claims, repeatable_claim_index);
		add_special_ip(&l3ctx.clientmgr_ctx, get_client(data->client->mac));
	}
}

void copy_intercom_task(struct intercom_task *old, struct intercom_task *new) {
	new->client = l3roamd_alloc(sizeof(struct client));
	memcpy(new->client, old->client, sizeof(struct client));

	new->packet_len = old->packet_len;
	new->packet = l3roamd_alloc(old->packet_len);
	memcpy(new->packet, old->packet, new->packet_len);

	new->recipient = NULL;
	new->check_task = old->check_task;
	if (old->recipient) {
		new->recipient = l3roamd_alloc_aligned(sizeof(struct in6_addr), sizeof(struct in6_addr));
		memcpy(new->recipient, old->recipient, sizeof(struct in6_addr));
	}

	new->retries_left = old->retries_left;
}

void schedule_retries(struct intercom_task *data, int ms_timeout, void (*processor)(void *data)) {
	if (data->retries_left == 0)
		return;

	struct intercom_task *ndata = l3roamd_alloc(sizeof(struct intercom_task));
	copy_intercom_task(data, ndata);
	ndata->retries_left--;

	ndata->check_task = post_task(&l3ctx.taskqueue_ctx, 0, ms_timeout, processor, free_intercom_task, ndata);
}

bool intercom_ack(intercom_ctx *ctx, const struct in6_addr *recipient, struct client *client) {
	log_verbose("sending ACK for client [%s] to %s\n", print_mac(client->mac), print_ip(recipient));

	intercom_packet_claim *packet = l3roamd_alloc(sizeof(intercom_packet_ack) + 8);

	int currentoffset = assemble_header(&packet->hdr, 255, INTERCOM_ACK);
	currentoffset += assemble_macinfo((void *)(packet) + currentoffset, client->mac, ACK_MAC);

	intercom_send_packet_unicast(ctx, recipient, (uint8_t *)packet, currentoffset);

	free(packet);
	return true;
}

bool intercom_claim(intercom_ctx *ctx, const struct in6_addr *recipient, struct client *client) {
	int i;

	if (find_repeatable(&l3ctx.intercom_ctx.repeatable_claims, client, &i))
		return true;

	log_verbose("CLAIMING client [%s]\n", print_mac(client->mac));

	struct intercom_task *data = l3roamd_alloc(sizeof(struct intercom_task));
	data->packet = l3roamd_alloc(sizeof(intercom_packet_claim) + 8);

	data->packet_len = assemble_header(&((intercom_packet_claim *)data->packet)->hdr, 255, INTERCOM_CLAIM);
	data->packet_len += assemble_macinfo((void *)(data->packet) + data->packet_len, client->mac, CLAIM_MAC);

	VECTOR_ADD(ctx->repeatable_claims, *client);

	data->client = l3roamd_alloc(sizeof(struct client));
	memcpy(data->client, client, sizeof(struct client));
	data->retries_left = CLAIM_RETRY_MAX;
	data->check_task = NULL;
	data->recipient = NULL;

	if (recipient) {
		data->recipient = l3roamd_alloc_aligned(sizeof(struct in6_addr), 16);
		memcpy(data->recipient, recipient, sizeof(struct in6_addr));
		((intercom_packet_claim *)data->packet)->hdr.ttl = 1;
	}

	client->claimed = true;

	data->check_task = post_task(&l3ctx.taskqueue_ctx, 0, 0, claim_retry_task, free_intercom_task, data);
	return true;
}
