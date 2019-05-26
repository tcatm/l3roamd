#pragma once

#include "arp.h"
#include "clientmgr.h"
#include "icmp6.h"
#include "if.h"
#include "intercom.h"
#include "ipmgr.h"
#include "routemgr.h"
#include "socket.h"
#include "taskqueue.h"
#include "types.h"
#include "vector.h"
#include "wifistations.h"

#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

struct l3ctx {
	taskqueue_ctx taskqueue_ctx;
	intercom_ctx intercom_ctx;
	clientmgr_ctx clientmgr_ctx;
	icmp6_ctx icmp6_ctx;
	ipmgr_ctx ipmgr_ctx;
	arp_ctx arp_ctx;
	routemgr_ctx routemgr_ctx;
	wifistations_ctx wifistations_ctx;
	socket_ctx socket_ctx;
	char *l3device;
	int client_mtu;
	int efd;
	bool debug;
	bool verbose;
	bool clientif_set;
};

extern l3ctx_t l3ctx;

void add_fd(int efd, int fd, uint32_t events);
void del_fd(int efd, int fd);

#define INTERCOM_PORT 5523
#define CTX(tgt) (&ctx->l3ctx->tgt##_ctx)
