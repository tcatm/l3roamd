#include "genl.h"
#include "error.h"
#include "wifistations.h"
#include "clientmgr.h"
#include "l3roamd.h"
#include "if.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
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

#include <linux/nl80211.h>

void wifistations_handle_in(wifistations_ctx *ctx) {
	nl_recvmsgs(ctx->nl_sock, ctx->cb);
}

int wifistations_handle_event(struct nl_msg *msg, void *arg) {
	wifistations_ctx *ctx = arg;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb[8];
	char macbuf[6*3];


	// TODO filtern auf interfaces, die uns interessieren
	// TODO liste von interfaces pflegen (netlink)

	printf("event %i\n", gnlh->cmd);

	char ifname[IFNAMSIZ];

	nla_parse(tb, 8, genlmsg_attrdata(gnlh, 0),
	genlmsg_attrlen(gnlh, 0), NULL);

	unsigned int ifindex = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);

	if_indextoname(ifindex, ifname);

	// TODO warum kann das NULL sein?
	if (gnlh == NULL)
		return 0;

	switch (gnlh->cmd) {
		case NL80211_CMD_NEW_STATION:
			mac_addr_n2a(macbuf, nla_data(tb[NL80211_ATTR_MAC]));

			printf("new wifi station [%s] found on interface %s\n", macbuf, ifname);
//			ifindex = ctx->l3ctx->icmp6_ctx.ifindex;
			clientmgr_notify_mac(CTX(clientmgr), nla_data(tb[NL80211_ATTR_MAC]), ifindex);
			break;
		case NL80211_CMD_DEL_STATION:
			// TODO: we should delete the client in a while instead of
			// just directly removing it. The client may have
			// roamed and we would like to allow for a
			// claim/info-cycle.
			printf("NL80211_CMD_DEL_STATION fpr [%s] RECEIVED on interface %s. Removing.\n", macbuf, ifname);
			clientmgr_delete_client(CTX(clientmgr), nla_data(tb[NL80211_ATTR_MAC]));
			break;
	}

	return 0;
}

void wifistations_init(wifistations_ctx *ctx) {
	ctx->nl_sock = nl_socket_alloc();
	if (!ctx->nl_sock)
		exit_error("Failed to allocate netlink socket.\n");

	nl_socket_set_buffer_size(ctx->nl_sock, 8192, 8192);
	/* no sequence checking for multicast messages */
	nl_socket_disable_seq_check(ctx->nl_sock);

	if (genl_connect(ctx->nl_sock)) {
		fprintf(stderr, "Failed to connect to generic netlink.\n");
		goto fail;
	}

	int nl80211_id = genl_ctrl_resolve(ctx->nl_sock, NL80211_GENL_NAME);
	if (nl80211_id < 0) {
		fprintf(stderr, "nl80211 not found.\n");
		/* To resolve issue #29 we do not bail out, but return with an
		 * invalid file descriptor and without a wifi socket instead.
		 */
		ctx->fd = -1;
		nl_socket_free(ctx->nl_sock);
		ctx->nl_sock = NULL;
		return;
	}

	/* MLME multicast group */
	int mcid = nl_get_multicast_id(ctx->nl_sock, NL80211_GENL_NAME, NL80211_MULTICAST_GROUP_MLME);
	if (mcid >= 0) {
		int ret = nl_socket_add_membership(ctx->nl_sock, mcid);
		if (ret)
			goto fail;
	}

	ctx->cb = nl_cb_alloc(NL_CB_DEFAULT);

	if (!ctx->cb)
		exit_error("failed to allocate netlink callbacks\n");

	nl_cb_set(ctx->cb, NL_CB_VALID, NL_CB_CUSTOM, wifistations_handle_event, ctx);

	ctx->fd = nl_socket_get_fd(ctx->nl_sock);

	return;

fail:
	nl_socket_free(ctx->nl_sock);
	exit_error("Could not open nl80211 socket");
}
