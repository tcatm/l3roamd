#pragma once
#include <netinet/in.h>

void print_ip(const struct in6_addr *addr, const char *term);
void log_verbose(const char *format, ...);
void log_debug(const char *format, ...);


