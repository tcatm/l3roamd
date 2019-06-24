/*
 * This file is part of project l3roamd. It's copyrighted by the contributors
 * recorded in the version control history of the file, available from
 * its original location https://github.com/freifunk-gluon/l3roamd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#pragma once

// declarations from <net/if.h>
extern unsigned int if_nametoindex(const char *__ifname);
extern char *if_indextoname(unsigned int __ifindex, char *__ifname);

// old kernel headers don't include this themselves
#include <sys/socket.h>

#include <linux/if.h>
