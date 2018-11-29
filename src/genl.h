#pragma once

#include <netlink/genl/genl.h>

int nl_get_multicast_id(struct nl_sock *sock, const char *family,
			const char *group);
