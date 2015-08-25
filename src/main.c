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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>

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

  intercom_seek(ctx, addr);
}

bool process_timer_entry(struct l3ctx *ctx, struct timespec now, const struct in6_addr *addr, struct ip_entry *entry) {
  entry->try++;

  printf("proces entry %i\n", entry->try);

  if (entry->try >= 4) {
    // TODO icmp unreachable senden
    return true;
  } else {
    entry->timeout = now.tv_sec + 1;

    establish_route(ctx, addr);

    return false;
  }
}

void handle_timer(struct l3ctx *ctx) {
  unsigned long long nEvents;

  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);

  read(ctx->timerfd, &nEvents, sizeof(nEvents));

  printf("timer\n");

  for (int i = 0; i < VECTOR_LEN(ctx->addrs); i++) {
    struct entry *e = &VECTOR_INDEX(ctx->addrs, i);

    if (e->v->timeout <= now.tv_sec) {
      bool delete = process_timer_entry(ctx, now, &e->k, e->v);

      if (delete)
        VECTOR_DELETE(ctx->addrs, i--);
    }
  }

  schedule(ctx);
}

void schedule(struct l3ctx *ctx) {
  time_t min;
  int i;

  for (i = 0; i < VECTOR_LEN(ctx->addrs); i++) {
    struct entry *e = &VECTOR_INDEX(ctx->addrs, i);

    if (e->v->timeout < min || i == 0)
      min = e->v->timeout;
  }

  if (i == 0)
    return;

  struct itimerspec t = {};
  t.it_value.tv_sec = min;

  timerfd_settime(ctx->timerfd, TFD_TIMER_ABSTIME, &t, NULL);
}

bool prefix_contains(const struct prefix *prefix, struct in6_addr *addr) {
  int plen = prefix->plen;

  for (int i = 0; i < 16; i++) {
    int mask = ~((1<<(8 - (plen > 8 ? 8 : plen))) - 1);

    if ((addr->s6_addr[i] & mask) != prefix->prefix.s6_addr[i])
      return false;

    plen -= 8;

    if (plen < 0)
      plen = 0;
  }
  return true;
}

void neighbour_discovered(struct l3ctx *ctx, struct in6_addr *addr, uint8_t mac[6]) {
  char target[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, addr, target, INET6_ADDRSTRLEN);

  if (!prefix_contains(&ctx->clientprefix, addr))
    return;

  printf("Target address of neighbor solicitation: %s\n", target);

  // TODO add route
  // TODO client merken

  struct kernel_route route = {
    .plen = 128,
    .proto = 23,
    .ifindex = if_nametoindex(ctx->clientif)
  };

  memcpy(route.prefix, addr->s6_addr, 16);

  insert_route(ctx, &route);
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

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    e->try = 0;
    e->timeout = now.tv_sec + 1;

    schedule(ctx);
  }

  struct packet *p = malloc(sizeof(struct packet));

  p->len = packet_len;
  p->data = malloc(packet_len);
  memcpy(p->data, packet, packet_len);

  VECTOR_ADD(e->packets, p);

  if (e->try == 0)
    establish_route(ctx, &dst);
}

void drain_output_queue(struct l3ctx *ctx) {
  tun_handle_out(ctx, ctx->tun.fd);
}

void loop(struct l3ctx *ctx) {
  int s;
  int efd;
  int maxevents = 64;
  struct epoll_event event;
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

  event.data.fd = ctx->timerfd;
  event.events = EPOLLIN;
  s = epoll_ctl(efd, EPOLL_CTL_ADD, ctx->timerfd, &event);
  if (s == -1)
    exit_error("epoll_ctl");

  event.data.fd = ctx->icmp6fd;
  event.events = EPOLLIN;
  s = epoll_ctl(efd, EPOLL_CTL_ADD, ctx->icmp6fd, &event);
  if (s == -1)
    exit_error("epoll_ctl");

  event.data.fd = ctx->intercomfd;
  event.events = EPOLLIN | EPOLLET;
  s = epoll_ctl(efd, EPOLL_CTL_ADD, ctx->intercomfd, &event);
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
      } else if (ctx->intercomfd == events[i].data.fd) {
        if (events[i].events & EPOLLIN)
          intercom_handle_in(ctx, events[i].data.fd);
      } else if (ctx->timerfd == events[i].data.fd) {
        handle_timer(ctx);
      }
    }
  }

  free(events);
}

int main(int argc, char *argv[]) {
  struct l3ctx ctx = {};

  inet_pton(AF_INET6, "2001:67c:2d50:41::", &(ctx.clientprefix.prefix));
  ctx.clientprefix.plen = 64;

  ctx.export_table = 11; // TODO konfigurierbar machen!

  ctx.clientif = "br-client";

  ctx.timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);

  list_new(&ctx.output_queue);

  tun_open(&ctx.tun, "l3roam0", 9000, "/dev/net/tun");

  rtnl_init(&ctx);

  icmp6_init(&ctx);

  intercom_init(&ctx, "mesh0");

  loop(&ctx);

  return 0;
}
