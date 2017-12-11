

#include "util.h"
#include <arpa/inet.h>
#include <stdio.h>

// TODO: where should we put this?
/* print a human-readable representation of an in6_addr struct to stdout
** */
void print_ip(const struct in6_addr *addr) {
	char a1[INET6_ADDRSTRLEN+1];
	inet_ntop(AF_INET6, addr, a1, INET6_ADDRSTRLEN);
	printf("%s", a1);
}

