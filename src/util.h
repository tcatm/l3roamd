#pragma once
#include <netinet/in.h>

const char* print_ip(const struct in6_addr *addr);
void log_verbose(const char *format, ...);
void log_debug(const char *format, ...);


