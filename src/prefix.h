#include <stdbool.h>
#include <netinet/in.h>
#include "vector.h"
#include <string.h>
#include <arpa/inet.h>

#ifndef INCLUDE_PREFIX
#define INCLUDE_PREFIX 

struct prefix {
	struct in6_addr prefix;
	int plen; /* in bits */
};

bool add_prefix(void *prefixes, struct prefix prefix);
bool del_prefix(void *prefixes, struct prefix prefix);
bool parse_prefix(struct prefix *prefix, const char *str);

#endif
