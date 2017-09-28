#pragma once

// declarations from <net/if.h>
extern unsigned int if_nametoindex (const char *__ifname);
extern char *if_indextoname (unsigned int __ifindex, char *__ifname);

// old kernel headers don't include this themselves
#include <sys/socket.h>

#include <linux/if.h>
