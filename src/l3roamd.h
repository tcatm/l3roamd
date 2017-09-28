#pragma once

#include "vector.h"
#include "intercom.h"
#include "wifistations.h"
#include "clientmgr.h"
#include "taskqueue.h"
#include "ipmgr.h"
#include "routemgr.h"
#include "socket.h"
#include "if.h"

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
	ipmgr_ctx ipmgr_ctx;
	routemgr_ctx routemgr_ctx;
	socket_ctx socket_ctx;
};

void interfaces_changed(struct l3ctx *ctx, int type, const struct ifinfomsg *msg);

#define CTX(tgt) (&ctx->l3ctx->tgt ## _ctx)
