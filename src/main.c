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
// TODO heap für timer events

#include "tun.h"
#include "l3roamd.h"
#include "error.h"
#include "icmp6.h"
#include "routes.h"
#include "intercom.h"
#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <fcntl.h>

struct ip_entry *find_entry(struct l3ctx *ctx, const struct in6_addr *k) {
  for (int i = 0; i < VECTOR_LEN(ctx->addrs); i++) {
    struct entry *e = &VECTOR_INDEX(ctx->addrs, i);

    if (memcmp(k, &(e->k), sizeof(struct in6_addr)) == 0)
      return e->v;
  }

  return NULL;
}

void delete_entry(struct l3ctx *ctx, const struct in6_addr *k) {
  for (int i = 0; i < VECTOR_LEN(ctx->addrs); i++) {
    struct entry *e = &VECTOR_INDEX(ctx->addrs, i);

    if (memcmp(k, &(e->k), sizeof(struct in6_addr)) == 0) {
      VECTOR_DELETE(ctx->addrs, i);
      break;
    }
  }
}

void establish_route(struct l3ctx *ctx, const struct in6_addr *addr) {
  char str[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, addr, str, sizeof str);

  printf("Establish route %s\n", str);

  icmp6_send_solicitation(ctx, addr);

  intercom_seek(&ctx->intercom_ctx, addr);
}

void handle_packet(struct l3ctx *ctx, uint8_t packet[], ssize_t packet_len) {
  struct in6_addr dst;
  memcpy(&dst, packet + 24, 16);

  uint8_t a0 = dst.s6_addr[0];

  // Check for dst in 2000::/3 or fc00::/7
  if ((a0 & 0xe0) != 0x20 && (a0 & 0xfe) != 0xfc)
    return;

  char str[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &dst, str, sizeof str);
  printf("Got packet to %s\n", str);

  struct ip_entry *e = find_entry(ctx, &dst);

  if (!e) {
    struct entry entry;
    entry.k = dst;
    entry.v = (struct ip_entry*)calloc(1, sizeof(struct ip_entry));

    VECTOR_ADD(ctx->addrs, entry);

    e = entry.v;
  }

  struct packet *p = malloc(sizeof(struct packet));

  p->len = packet_len;
  p->data = malloc(packet_len);
  memcpy(p->data, packet, packet_len);

  VECTOR_ADD(e->packets, p);

  establish_route(ctx, &dst);
}

void drain_output_queue(struct l3ctx *ctx) {
  tun_handle_out(ctx, ctx->tun.fd);
}

void loop(struct l3ctx *ctx) {
  int s;
  int efd;
  int maxevents = 64;
  struct epoll_event event = {};
  struct epoll_event *events;

  efd = epoll_create1(0);
  if (efd == -1) {
    perror("epoll_create");
    abort();
  }

  event.data.fd = ctx->tun.fd;
  event.events = EPOLLIN | EPOLLET;
  s = epoll_ctl(efd, EPOLL_CTL_ADD, ctx->tun.fd, &event);
  if (s == -1)
    exit_error("epoll_ctl");

  event.data.fd = ctx->rtnl_sock;
  event.events = EPOLLIN | EPOLLET;
  s = epoll_ctl(efd, EPOLL_CTL_ADD, ctx->rtnl_sock, &event);
  if (s == -1)
    exit_error("epoll_ctl");

  event.data.fd = ctx->taskqueue_ctx.fd;
  event.events = EPOLLIN;
  s = epoll_ctl(efd, EPOLL_CTL_ADD, ctx->taskqueue_ctx.fd, &event);
  if (s == -1)
    exit_error("epoll_ctl");

  event.data.fd = ctx->icmp6fd;
  event.events = EPOLLIN;
  s = epoll_ctl(efd, EPOLL_CTL_ADD, ctx->icmp6fd, &event);
  if (s == -1)
    exit_error("epoll_ctl");

  event.data.fd = ctx->icmp6nsfd;
  event.events = EPOLLIN;
  s = epoll_ctl(efd, EPOLL_CTL_ADD, ctx->icmp6nsfd, &event);
  if (s == -1)
    exit_error("epoll_ctl");

  event.data.fd = ctx->intercom_ctx.fd;
  event.events = EPOLLIN | EPOLLET;
  s = epoll_ctl(efd, EPOLL_CTL_ADD, ctx->intercom_ctx.fd, &event);
  if (s == -1)
    exit_error("epoll_ctl");

  event.data.fd = ctx->wifistations_ctx.fd;
  event.events = EPOLLIN;
  s = epoll_ctl(efd, EPOLL_CTL_ADD, ctx->wifistations_ctx.fd, &event);
  if (s == -1)
    exit_error("epoll_ctl");

  /* Buffer where events are returned */
  events = calloc(maxevents, sizeof event);

  /* The event loop */
  while (1) {
    int n, i;

    n = epoll_wait(efd, events, maxevents, -1);
    for(i = 0; i < n; i++) {
      if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)) {
        fprintf(stderr, "epoll error\n");
        close(events[i].data.fd);
      } else if (ctx->rtnl_sock == events[i].data.fd) {
        if (events[i].events & EPOLLIN)
          rtnl_handle_in(ctx, events[i].data.fd);
      } else if (ctx->tun.fd == events[i].data.fd) {
        if (events[i].events & EPOLLIN)
          tun_handle_in(ctx, events[i].data.fd);
      } else if (ctx->icmp6fd == events[i].data.fd) {
        if (events[i].events & EPOLLIN)
          icmp6_handle_in(ctx, events[i].data.fd);
      } else if (ctx->icmp6nsfd == events[i].data.fd) {
        if (events[i].events & EPOLLIN)
          icmp6_handle_ns_in(ctx, events[i].data.fd);
      } else if (ctx->intercom_ctx.fd == events[i].data.fd) {
        if (events[i].events & EPOLLIN)
          intercom_handle_in(&ctx->intercom_ctx, ctx, events[i].data.fd);
      } else if (ctx->taskqueue_ctx.fd == events[i].data.fd) {
        taskqueue_run(&ctx->taskqueue_ctx);
      } else if (ctx->wifistations_ctx.fd == events[i].data.fd) {
        wifistations_handle_in(&ctx->wifistations_ctx);
      }
    }
  }

  free(events);
}

void usage() {
  puts("Usage: l3roamd [-h] -a <ip6> -p <prefix> -i <clientif> -m <meshif> ... -t <export table>");
  puts("  -a <ip6>          ip address of this node");
  puts("  -p <prefix>       clientprefix"); // TODO mehrfache angabe sollte möglich sein
  puts("  -i <clientif>     client interface");
  puts("  -m <meshif>       mesh interface. may be specified multiple times");
  puts("  -t <export table> export routes to this table");
  puts("  -h                this help\n");
}

bool parse_prefix(struct prefix *prefix, const char *str) {
  char *saveptr;
  char *tmp = strdupa(str);
  char *ptr = strtok_r(tmp, "/", &saveptr);

  if (ptr == NULL)
    return false;

  int rc = inet_pton(AF_INET6, ptr, &prefix->prefix);

  if (rc != 1)
    return false;

  ptr = strtok_r(NULL, "/", &saveptr);

  if (ptr == NULL)
    return false;

  prefix->plen = atoi(ptr);

  if (prefix->plen < 0 || prefix->plen > 128)
    return false;

  return true;
}

static void init_random(void) {
	unsigned int seed;
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		exit_errno("can't open /dev/urandom");

	if (read(fd, &seed, sizeof(seed)) != sizeof(seed))
		exit_errno("can't read from /dev/urandom");

	close(fd);

	srandom(seed);
}

void interfaces_changed(struct l3ctx *ctx, int type, const struct ifinfomsg *msg) {
  printf("interfaces changed\n");
  intercom_update_interfaces(&ctx->intercom_ctx);
  icmp6_interface_changed(ctx, type, msg);
}

int main(int argc, char *argv[]) {
  struct l3ctx ctx = {};

  init_random();

  intercom_init(&ctx.intercom_ctx);

  int c;
  while ((c = getopt(argc, argv, "ha:p:i:m:t:c:")) != -1)
    switch (c) {
      case 'h':
        usage();
        exit(EXIT_SUCCESS);
      case 'a':
        if(inet_pton(AF_INET6, optarg, &ctx.intercom_ctx.ip) != 1)
          exit_error("Can not parse IP address");

	break;
      case 'c':
	parse_config(optarg);
        break;
      case 'p':
        if (!parse_prefix(&ctx.clientmgr_ctx.prefix, optarg))
          exit_error("Can not parse prefix");

        printf("plen %i\n", ctx.clientmgr_ctx.prefix.plen);
        break;
      case 'i':
        ctx.clientif = strdupa(optarg);
        break;
      case 'm':
        intercom_add_interface(&ctx.intercom_ctx, strdupa(optarg));
        break;
      case 't':
        ctx.clientmgr_ctx.export_table = atoi(optarg);
        break;
      default:
        fprintf(stderr, "Invalid parameter %c ignored.\n", c);
    }

  list_new(&ctx.output_queue);

  tun_open(&ctx.tun, "l3roam0", 9000, "/dev/net/tun");

  rtnl_init(&ctx);

  icmp6_init(&ctx);

  taskqueue_init(&ctx.taskqueue_ctx);

  wifistations_init(&ctx.wifistations_ctx, &ctx);

  loop(&ctx);

  return 0;
}
