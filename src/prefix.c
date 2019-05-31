/*
 * Copyright (c) 2017,2018 Christof Schulze <christof@christofschulze.com>
 *
 * This file is part of project l3roamd. It's copyrighted by the contributors
 * recorded in the version control history of the file, available from
 * its original location https://github.com/freifunk-gluon/l3roamd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "prefix.h"
#include <string.h>

#include <stdio.h>
#include "util.h"
/* this will parse the string str and return a prefix struct
*/
bool parse_prefix(struct prefix *prefix, const char *str) {
	char *saveptr;
	char *tmp = strdup(str);

	prefix->isv4 = true;
	if (strchr(tmp, ':'))
		prefix->isv4 = false;

	log_debug("parsing prefix %s, ipv4-state: %i\n", str, prefix->isv4);

	char *ptr = strtok_r(tmp, "/", &saveptr);

	if (prefix->isv4) {
		struct in_addr v4;
		if (inet_pton(AF_INET, ptr, &v4) != 1)
			goto error;
		mapv4_v6(&v4, &prefix->prefix);
	} else {
		if (inet_pton(AF_INET6, ptr, &prefix->prefix) != 1)
			goto error;
	}
	ptr = strtok_r(NULL, "/", &saveptr);
	if (ptr == NULL)
		goto error;

	prefix->plen = atoi(ptr);
	if (prefix->isv4)
		prefix->plen += 96;

	if (prefix->plen < 0 || prefix->plen > 128)
		goto error;

	free(tmp);
	return true;

error:
	free(tmp);
	return false;
}

/* this will add a prefix to the prefix vector, causing l3roamd  to
** accept packets to this prefix as client-prefix
*/
bool add_prefix(void *prefixes, struct prefix _prefix) {
	VECTOR(struct prefix) *_prefixes = prefixes;
	VECTOR_ADD(*_prefixes, _prefix);

	return true;
}

/* this will remove a prefix from the prefix vector, causing l3roamd not to
** accept packets to this prefix as client-prefix
*/
bool del_prefix(void *prefixes, struct prefix _prefix) {
	VECTOR(struct prefix) *_prefixes = prefixes;
	for (int i = 0; i < VECTOR_LEN(*_prefixes); i++) {
		if (!memcmp(&VECTOR_INDEX(*_prefixes, i), &_prefix,
			    sizeof(_prefix))) {
			VECTOR_DELETE(*_prefixes, i);
			return true;
		}
	}

	return false;
}

bool prefix_contains(const struct prefix *prefix, const struct in6_addr *addr) {
	log_debug("checking if prefix %s contains address %s\n",
		  print_ip(&prefix->prefix), print_ip(addr));

	int mask = 0xff;
	for (int remaining_plen = prefix->plen, i = 0; remaining_plen > 0;
	     remaining_plen -= 8) {
		if (remaining_plen < 8)
			mask = 0xff & (0xff00 >> remaining_plen);

		if ((addr->s6_addr[i] & mask) != prefix->prefix.s6_addr[i])
			return false;
		i++;
	}
	return true;
}
