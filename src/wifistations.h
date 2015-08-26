#pragma once

#include "vector.h"
#include <stdbool.h>

typedef struct {
  char *ifname;
  unsigned int ifindex;
  bool ok;
} wifistations_if;

typedef struct {
  int fd;
  struct nl_sock *nl_sock;
  struct nl_cb *cb;
  VECTOR(wifistations_if) interfaces;
} wifistations_ctx;

struct l3ctx;

void wifistations_handle_in(wifistations_ctx *ctx);
void wifistations_init(wifistations_ctx *ctx, struct l3ctx *l3ctx);
