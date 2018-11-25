#pragma once

#include "timespec.h"
#include <stdint.h>
#include <sys/types.h>

struct packet {
	struct timespec timestamp;
	ssize_t len;
	uint8_t *data;
	uint8_t family;
};


uint16_t packet_ipv4_get_length(const uint8_t packet[]);
uint8_t packet_ipv4_get_header_length(const uint8_t packet[]);
struct in6_addr packet_get_src(const uint8_t packet[]);
struct in6_addr packet_get_dst(const uint8_t packet[]);
uint8_t packet_get_family(const uint8_t packet[]);
