

#include "util.h"
#include <arpa/inet.h>
#include <stdio.h>
#include "l3roamd.h"
#include "error.h"
#include <sys/epoll.h>

#define STRBUFELEMENTS 2

static char strbuffer[STRBUFELEMENTS][INET6_ADDRSTRLEN+1];
static int str_bufferoffset = 0;

const char *print_ip4(const struct in_addr *addr) {
	str_bufferoffset = ( str_bufferoffset + 1) % STRBUFELEMENTS;
	return inet_ntop(AF_INET, &(addr->s_addr), strbuffer[str_bufferoffset], INET6_ADDRSTRLEN);
}

/* print a human-readable representation of an in6_addr struct to stdout
** */
const char *print_ip(const struct in6_addr *addr) {
	str_bufferoffset = ( str_bufferoffset + 1) % STRBUFELEMENTS;
	return inet_ntop(AF_INET6, &(addr->s6_addr), strbuffer[str_bufferoffset], INET6_ADDRSTRLEN);
}

const char *print_mac(const uint8_t *mac) {
	str_bufferoffset = ( str_bufferoffset + 1) % STRBUFELEMENTS;
	snprintf(strbuffer[str_bufferoffset], 18, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return strbuffer[str_bufferoffset];
}

struct in_addr inline extractv4_v6(const struct in6_addr *src) {
        struct in_addr tmp = {
            .s_addr = src->s6_addr[12] << 24 | src->s6_addr[13] << 16 | src->s6_addr[14] << 8 | src->s6_addr[15]
        };
	struct in_addr ip4;
	ip4.s_addr = ntohl(tmp.s_addr);
	return ip4;
}

void inline mapv4_v6(const struct in_addr *src, struct in6_addr *dst) {
	memcpy(dst, &l3ctx.clientmgr_ctx.v4prefix,12);
	memcpy(&(dst->s6_addr)[12], src, 4);
}

void log_error(const char *format, ...) {
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}

void log_debug(const char *format, ...) {
	if (!l3ctx.debug)
		return;
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}

void log_verbose(const char *format, ...) {
	if (!l3ctx.verbose)
		return;
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}

/** Check whether an IP address is contained in the IPv4 prefix or the empty prefix.
  */
bool inline address_is_ipv4(const struct in6_addr *address) {
	return prefix_contains(&l3ctx.clientmgr_ctx.v4prefix, address);
}

void add_fd ( int efd, int fd, uint32_t events )
{
    struct epoll_event event = {};
    event.data.fd = fd;
    event.events = events;

    int s = epoll_ctl ( efd, EPOLL_CTL_ADD, fd, &event );
    if ( s == -1 ) {
        perror ( "epoll_ctl (ADD):" );
        exit_error ( "epoll_ctl" );
    }
}

void del_fd ( int efd, int fd )
{
    int s = epoll_ctl ( efd, EPOLL_CTL_DEL, fd, NULL );
    if ( s == -1 ) {
        perror ( "epoll_ctl (DEL):" );
        exit_error ( "epoll_ctl" );
    }
}

void interfaces_changed ( int type, const struct ifinfomsg *msg )
{
    printf ( "interfaces changed\n" );
    intercom_update_interfaces ( &l3ctx.intercom_ctx );
    icmp6_interface_changed ( &l3ctx.icmp6_ctx, type, msg );
    arp_interface_changed ( &l3ctx.arp_ctx, type, msg );
    // TODO: re-initialize routemgr-fd
    // TODO: re-initialize ipmgr-fd
    // TODO: re-initialize wifistations-fd
}
