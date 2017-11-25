/*
   Copyright (c) 2015, Nils Schneider <nils@nilsschneider.net>
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
   CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */

// TODO EPOLLOUT beim schreiben auf den tunfd

#include "vector.h"
#include "ipmgr.h"
#include "error.h"
#include "routemgr.h"
#include "intercom.h"
#include "config.h"
#include "socket.h"
#include "prefix.h"
#include "l3roamd.h"

#define SIGTERM_MSG "Exiting. Removing routes for prefixes and clients.\n"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <fcntl.h>
#include <signal.h>

struct l3ctx ctx = {};

void add_fd(int efd, int fd, uint32_t events) {
	struct epoll_event event = {};
	event.data.fd = fd;
	event.events = events;

	int s = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
	if (s == -1)
		exit_error("epoll_ctl");
}

void loop(struct l3ctx *ctx) {
	int efd;
	int maxevents = 64;
	struct epoll_event *events;

	efd = epoll_create1(0);
	if (efd == -1) {
		perror("epoll_create");
		abort();
	}

	add_fd(efd, ctx->ipmgr_ctx.fd, EPOLLIN | EPOLLET);
	add_fd(efd, ctx->routemgr_ctx.fd, EPOLLIN | EPOLLET);
	add_fd(efd, ctx->intercom_ctx.fd, EPOLLIN | EPOLLET);
	add_fd(efd, ctx->taskqueue_ctx.fd, EPOLLIN);
	if (ctx->socket_ctx.fd >= 0) {
		add_fd(efd, ctx->socket_ctx.fd, EPOLLIN);
	}

	if (ctx->wifistations_ctx.fd >= 0) {
		add_fd(efd, ctx->wifistations_ctx.fd, EPOLLIN);
	}

	/* Buffer where events are returned */
	events = calloc(maxevents, sizeof(struct epoll_event));

	/* The event loop */
	while (1) {
		int n;
		n = epoll_wait(efd, events, maxevents, -1);
		for(int i = 0; i < n; i++) {
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)) {
				fprintf(stderr, "epoll error\n");
				close(events[i].data.fd);
				// TODO: routemgr is handling routes from kernel AND direct neighbours from fdb.
				// Refactor this at is actually a netlink-handler
			} else if (ctx->taskqueue_ctx.fd == events[i].data.fd) {
				taskqueue_run(&ctx->taskqueue_ctx);
			} else if (ctx->routemgr_ctx.fd == events[i].data.fd) {
				if (events[i].events & EPOLLIN)
					routemgr_handle_in(&ctx->routemgr_ctx, events[i].data.fd);
			} else if (ctx->ipmgr_ctx.fd == events[i].data.fd) {
				if (events[i].events & EPOLLIN)
					ipmgr_handle_in(&ctx->ipmgr_ctx, events[i].data.fd);
			} else if (ctx->intercom_ctx.fd == events[i].data.fd) {
				if (events[i].events & EPOLLIN)
					intercom_handle_in(&ctx->intercom_ctx, events[i].data.fd);
			} else if (ctx->socket_ctx.fd == events[i].data.fd) {
				socket_handle_in(&ctx->socket_ctx);
			} else if (ctx->wifistations_ctx.fd == events[i].data.fd) {
				wifistations_handle_in(&ctx->wifistations_ctx);
			}
		}
	}

	free(events);
}

void usage() {
	puts("Usage: l3roamd [-h] [-b <client-bridge>] -a <ip6> -p <prefix> [-i <clientif>] -m <meshif> ... -t <export table> -4 [prefix] -t <nat46if>");
	puts("  -a <ip6>           ip address of this node");
	puts("  -b <client-bridge> this is the bridge where all clients are connected");
	puts("  -c <file>          configuration file"); // TODO: do we really need this?
	puts("  -p <prefix>        Accept queries for this prefix. May be provided multiple times.");
	puts("  -s <socketpath>    provide statistics and allow control using this socket. See below for usage instructions.");
	puts("  -i <clientif>      client interface");
	puts("  -m <meshif>        mesh interface. may be specified multiple times");
	puts("  -t <export table>  export routes to this table");
	puts("  -4 <prefix>        IPv4 translation prefix");
	puts("  -t <nat46if>       interface for nat46");
	puts("  -h                 this help\n\n");
	puts("The socket will accept the following commands:");
	puts("get_clients          The daemon will reply with a json structure, currently providing client count.");
	puts("add_prefix <prefix>  This will treat <prefix> as if it was added using -p");
	puts("del_prefix <prefix>  This will remove <prefix> from the list of client-prefixes and stop accepting queries for clients within that prefix.");
}


void interfaces_changed(struct l3ctx *ctx, int type, const struct ifinfomsg *msg) {
	printf("interfaces changed\n");
	intercom_update_interfaces(&ctx->intercom_ctx);
}

void sig_term_handler(int signum, siginfo_t *info, void *ptr)
{
	write(STDERR_FILENO, SIGTERM_MSG, sizeof(SIGTERM_MSG));
	int j = VECTOR_LEN(ctx.clientmgr_ctx.prefixes);

	struct prefix _prefix = {};
	for (int i=j;i>0;i--) {
		del_prefix(&ctx.clientmgr_ctx.prefixes, _prefix);
		routemgr_remove_route(&ctx.routemgr_ctx, 254, (struct in6_addr*)(_prefix.prefix.s6_addr), _prefix.plen );
	}
	clientmgr_purge_clients(&ctx.clientmgr_ctx);
	_exit(EXIT_SUCCESS);
}


void catch_sigterm()
{
	static struct sigaction _sigact;

	memset(&_sigact, 0, sizeof(_sigact));
	_sigact.sa_sigaction = sig_term_handler;
	_sigact.sa_flags = SA_SIGINFO;

	sigaction(SIGTERM, &_sigact, NULL);
}


int main(int argc, char *argv[]) {
	char *socketpath = NULL;

	signal(SIGPIPE, SIG_IGN);
	catch_sigterm();

	ctx.wifistations_ctx.l3ctx = &ctx;
	ctx.clientmgr_ctx.l3ctx = &ctx;
	ctx.intercom_ctx.l3ctx = &ctx;
	ctx.ipmgr_ctx.l3ctx = &ctx;
	ctx.routemgr_ctx.l3ctx = &ctx;
	ctx.socket_ctx.l3ctx = &ctx;
	ctx.taskqueue_ctx.l3ctx = &ctx;

	intercom_init(&ctx.intercom_ctx);
	ctx.routemgr_ctx.client_bridge = strdup("\0");
	ctx.routemgr_ctx.clientif = strdup("\0");
	ctx.clientmgr_ctx.export_table = 254;
	bool v4_initialized=false;
	bool a_initialized=false;
	bool p_initialized=false;

	int c;
	while ((c = getopt(argc, argv, "ha:b:p:i:m:t:c:4:n:s:")) != -1)
		switch (c) {
			case 'b':
				free(ctx.routemgr_ctx.client_bridge);
				ctx.routemgr_ctx.client_bridge = strdupa(optarg);
				break;
			case 'h':
				usage();
				exit(EXIT_SUCCESS);
			case 'a':
				if(inet_pton(AF_INET6, optarg, &ctx.intercom_ctx.ip) != 1)
					exit_error("Can not parse IP address");
				a_initialized=true;
				break;
			case 'c':
				parse_config(optarg);
				break;
			case 'p':
				p_initialized=true;

				struct prefix _prefix = {};
				if (!parse_prefix(&_prefix, optarg))
					exit_error("Can not parse prefix");
				if (_prefix.plen != 64)
					exit_error("IPv6 prefix must be /64");

				add_prefix(&ctx.clientmgr_ctx.prefixes, _prefix);
				break;
			case 'i':
				free(ctx.routemgr_ctx.clientif);
				ctx.routemgr_ctx.clientif = strdupa(optarg);
				break;
			case 'm':
				intercom_add_interface(&ctx.intercom_ctx, strdupa(optarg));
				break;
			case 't':
				ctx.clientmgr_ctx.export_table = atoi(optarg);
				break;
			case 's':
				socketpath = optarg;
				break;
			case '4':
				if (!parse_prefix(&ctx.clientmgr_ctx.v4prefix, optarg))
					exit_error("Can not parse IPv4 prefix");

				if (ctx.clientmgr_ctx.v4prefix.plen != 96)
					exit_error("IPv4 prefix must be /96");

				v4_initialized=true;
				break;
			case 'n':
				ctx.clientmgr_ctx.nat46ifindex = if_nametoindex(optarg);
				break;
			default:
				fprintf(stderr, "Invalid parameter %c ignored.\n", c);
		}


	if (!v4_initialized)
		exit_error("specifying -4 is mandatory even though it is untested and probably broken. If in doubt, use -4 0:0:0:0:0:ffff::/96");
	if (!a_initialized)
		exit_error("specifying -a is mandatory");
	if (!p_initialized)
		exit_error("specifying -p is mandatory");

	socket_init(&ctx.socket_ctx, socketpath);
	ipmgr_init(&ctx.ipmgr_ctx, "l3roam0", 9000);
	routemgr_init(&ctx.routemgr_ctx);
	wifistations_init(&ctx.wifistations_ctx);
	taskqueue_init(&ctx.taskqueue_ctx);

	loop(&ctx);

	return 0;
}
