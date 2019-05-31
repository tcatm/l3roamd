/*
 * This file is part of project l3roamd. It's copyrighted by the contributors
 * recorded in the version control history of the file, available from
 * its original location https://github.com/freifunk-gluon/l3roamd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "packet.h"
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>
#include "util.h"

static struct in6_addr packet_get_ip4(const uint8_t packet[], int offset) {
	struct in_addr src;
	struct in6_addr src6;
	memcpy(&src, packet + offset, 4);
	mapv4_v6(&src, &src6);
	return src6;
}

static struct in6_addr packet_get_src4(const uint8_t packet[]) {
	return packet_get_ip4(packet, 12);
}

static struct in6_addr packet_get_dst4(const uint8_t packet[]) {
	return packet_get_ip4(packet, 16);
}

static struct in6_addr packet_get_ip6(const uint8_t packet[], int offset) {
	struct in6_addr src;
	memcpy(&src, packet + offset, 16);
	return src;
}

static struct in6_addr packet_get_src6(const uint8_t packet[]) {
	return packet_get_ip6(packet, 8);
}

static struct in6_addr packet_get_dst6(const uint8_t packet[]) {
	return packet_get_ip6(packet, 24);
}

uint8_t packet_ipv4_get_header_length(const uint8_t packet[]) {
	return (packet[0] & 0x0f) << 2;  // IHL * 32 / 8 = IHL * 32/4 = IHL << 2
}

uint16_t packet_ipv4_get_length(const uint8_t packet[]) {
	uint16_t length = ((packet[3] << 8) | packet[4]);
	return length;
}

static bool packet_isv4(const uint8_t packet[]) {
	return (packet[0] & 0xf0) == 0x40;
}

static bool packet_isv6(const uint8_t packet[]) {
	return (packet[0] & 0xf0) == 0x60;
}

uint8_t packet_get_family(const uint8_t packet[]) {
	return (packet_isv6(packet) ? AF_INET6 : AF_INET);
}

struct in6_addr packet_get_src(const uint8_t packet[]) {
	if (packet_isv4(packet))
		return packet_get_src4(packet);
	else if (packet_isv6(packet))
		return packet_get_src6(packet);
	struct in6_addr ret = {};
	return ret;
}

struct in6_addr packet_get_dst(const uint8_t packet[]) {
	if (packet_isv4(packet))
		return packet_get_dst4(packet);
	else if (packet_isv6(packet))
		return packet_get_dst6(packet);
	struct in6_addr ret = {};
	return ret;
}
