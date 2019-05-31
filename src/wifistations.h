/*
 * This file is part of project l3roamd. It's copyrighted by the contributors
 * recorded in the version control history of the file, available from
 * its original location https://github.com/freifunk-gluon/l3roamd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#pragma once

#include <stdbool.h>
#include "vector.h"

typedef struct {
	char *ifname;
	unsigned int ifindex;
	bool ok;
} wifistations_if;

typedef struct {
	struct l3ctx *l3ctx;
	struct nl_sock *nl_sock;
	struct nl_cb *cb;
	VECTOR(wifistations_if) interfaces;
	int fd;
	bool nl80211_disabled;
} wifistations_ctx;

void wifistations_handle_in(wifistations_ctx *ctx);
void wifistations_init(wifistations_ctx *ctx);
