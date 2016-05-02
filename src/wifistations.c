#include "genl.h"
#include "error.h"
#include "wifistations.h"
#include "clientmgr.h"
#include "l3roamd.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#define NL80211_CMD_NEW_STATION 19
#define NL80211_CMD_DEL_STATION 20
#define NL80211_ATTR_IFINDEX 3
#define NL80211_ATTR_MAC 6

static int no_seq_check(struct nl_msg *msg, void *arg) {
	return NL_OK;
}

void mac_addr_n2a(char *mac_addr, unsigned char *arg) {
	int i, l;

	l = 0;
	for (i = 0; i < 6; i++) {
		if (i == 0) {
			sprintf(mac_addr+l, "%02x", arg[i]);
			l += 2;
		} else {
			sprintf(mac_addr+l, ":%02x", arg[i]);
			l += 3;
		}
	}
}

void wifistations_handle_in(wifistations_ctx *ctx) {
  nl_recvmsgs(ctx->nl_sock, ctx->cb);
}

int wifistations_handle_event(struct nl_msg *msg, void *arg) {
	struct l3ctx *ctx = arg;
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *tb[8];
  char macbuf[6*3];


  // TODO filtern auf interfaces, die uns interessieren
  // TODO liste von interfaces pflegen (netlink)

  printf("event %i\n", gnlh->cmd);

  char ifname[100];

  nla_parse(tb, 8, genlmsg_attrdata(gnlh, 0),
  genlmsg_attrlen(gnlh, 0), NULL);

	unsigned int ifindex = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);

  if_indextoname(ifindex, ifname);
  printf("%s: ", ifname);

	// TODO warum kann das NULL sein?
		if (gnlh == NULL)
			return 0;

  switch (gnlh->cmd) {
    case NL80211_CMD_NEW_STATION:
      mac_addr_n2a(macbuf, nla_data(tb[NL80211_ATTR_MAC]));

      printf("new station %s\n", macbuf);

			// FIXME Hack for br-client
			ifindex = ctx->icmp6_ctx.ifindex;
			clientmgr_add_client(&ctx->clientmgr_ctx, nla_data(tb[NL80211_ATTR_MAC]), ifindex);
      break;
    case NL80211_CMD_DEL_STATION:
      break;
  }

	return 0;
}

void wifistations_init(wifistations_ctx *ctx, struct l3ctx *l3ctx) {
	ctx->nl_sock = nl_socket_alloc();
	if (!ctx->nl_sock)
		exit_error("Failed to allocate netlink socket.\n");

	nl_socket_set_buffer_size(ctx->nl_sock, 8192, 8192);

	if (genl_connect(ctx->nl_sock)) {
		fprintf(stderr, "Failed to connect to generic netlink.\n");
		goto fail;
	}

	int nl80211_id = genl_ctrl_resolve(ctx->nl_sock, "nl80211");
	if (nl80211_id < 0) {
		fprintf(stderr, "nl80211 not found.\n");
		goto fail;
	}

  /* MLME multicast group */
  int mcid = nl_get_multicast_id(ctx->nl_sock, "nl80211", "mlme");
  if (mcid >= 0) {
    int ret = nl_socket_add_membership(ctx->nl_sock, mcid);
    if (ret)
      goto fail;
  }

  ctx->cb = nl_cb_alloc(NL_CB_DEFAULT);

  if (!ctx->cb)
    exit_error("failed to allocate netlink callbacks\n");

  /* no sequence checking for multicast messages */
  nl_cb_set(ctx->cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
  nl_cb_set(ctx->cb, NL_CB_VALID, NL_CB_CUSTOM, wifistations_handle_event, l3ctx);

  ctx->fd = nl_socket_get_fd(ctx->nl_sock);

	return;

fail:
	nl_socket_free(ctx->nl_sock);
  exit_error("Could not open nl80211 socket");
}
