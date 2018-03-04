#pragma once

#include "vector.h"
#include "intercom.h"
#include "wifistations.h"
#include "clientmgr.h"
#include "taskqueue.h"
#include "icmp6.h"
#include "ipmgr.h"
#include "arp.h"
#include "routemgr.h"
#include "socket.h"
#include "if.h"
#include "types.h"

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>

struct l3ctx {
	taskqueue_ctx taskqueue_ctx;
	intercom_ctx intercom_ctx;
	wifistations_ctx wifistations_ctx;
	clientmgr_ctx clientmgr_ctx;
	icmp6_ctx icmp6_ctx;
	ipmgr_ctx ipmgr_ctx;
	char *l3device;
	arp_ctx arp_ctx;
	routemgr_ctx routemgr_ctx;
	socket_ctx socket_ctx;
	bool debug;
	int efd;
};

extern l3ctx_t l3ctx;

void interfaces_changed(int type, const struct ifinfomsg *msg);
void add_fd(int efd, int fd, uint32_t events);
void del_fd(int efd, int fd);

#define INTERCOM_PORT 5523
#define CTX(tgt) (&ctx->l3ctx->tgt ## _ctx)
