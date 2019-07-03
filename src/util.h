/*
 * This file is part of project l3roamd. It's copyrighted by the contributors
 * recorded in the version control history of the file, available from
 * its original location https://github.com/freifunk-gluon/l3roamd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#pragma once
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <stdbool.h>

#define STRBUFELEMENTLEN 64
#define STRBUFLEN 256
#define STRBUFELEMENTS (STRBUFLEN / STRBUFELEMENTLEN)

union buffer {
	char element[STRBUFLEN / STRBUFELEMENTLEN][STRBUFELEMENTLEN];
	char allofit[STRBUFLEN];
};

struct in_addr extractv4_v6(const struct in6_addr *src);
void mapv4_v6(const struct in_addr *src, struct in6_addr *dst);
void obtain_mac_from_if(uint8_t dest[6], char ifname[]);
const char *print_ip4(const struct in_addr *addr);
const char *print_ip(const struct in6_addr *addr);
const char *print_mac(const uint8_t *mac);
const char *print_timespec(const struct timespec *t);
void log_verbose(const char *format, ...);
void log_debug(const char *format, ...);
void log_error(const char *format, ...);

void add_fd(int efd, int fd, uint32_t events);
void del_fd(int efd, int fd);
void interfaces_changed(int type, const struct ifinfomsg *msg);

bool address_is_ipv4(const struct in6_addr *ip);
