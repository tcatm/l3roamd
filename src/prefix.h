/*
 * Copyright (c) 2017, Christof Schulze <christof@christofschulze.com>
 *
 * This file is part of project l3roamd. It's copyrighted by the contributors
 * recorded in the version control history of the file, available from
 * its original location https://github.com/freifunk-gluon/l3roamd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include "vector.h"

struct prefix {
	struct in6_addr prefix;
	int plen; /* in bits */
	bool isv4;
};

bool add_prefix(void *prefixes, struct prefix prefix);
bool del_prefix(void *prefixes, struct prefix prefix);
bool parse_prefix(struct prefix *prefix, const char *str);
bool prefix_contains(const struct prefix *prefix, const struct in6_addr *addr);
