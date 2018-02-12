#include "routemgr.h"
#include "error.h"
#include "l3roamd.h"

#include "clientmgr.h"
#include "if.h"
#include <unistd.h>
#include "icmp6.h"
#include "util.h"

static void rtnl_change_address(routemgr_ctx *ctx, struct in6_addr *address, int type, int flags);
static void rtnl_handle_link(routemgr_ctx *ctx, const struct nlmsghdr *nh);
static int rtnl_addattr(struct nlmsghdr *n, int maxlen, int type, void *data, int datalen);
static void rtmgr_rtnl_talk(routemgr_ctx *ctx, struct nlmsghdr *req);

int parse_rtattr_flags(struct rtattr *tb[], int max, struct rtattr *rta,
		int len, unsigned short flags)
{
	unsigned short type;

	while (RTA_OK(rta, len)) {
		type = rta->rta_type & ~flags;
		if ((type <= max) && (!tb[type])) {
			tb[type] = rta;
		}
		rta = RTA_NEXT(rta,len);
	}
	if (len)
		fprintf(stderr, "!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
	return 0;
}

int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	return parse_rtattr_flags(tb, max, rta, len, 0);
}

void rtmgr_client_remove_address(struct in6_addr *dst_address) {
	struct client *_client = NULL;
	if (clientmgr_is_known_address(&l3ctx.clientmgr_ctx, dst_address, &_client)) {
		clientmgr_remove_address(&l3ctx.clientmgr_ctx, _client, dst_address);
		for (int i=0; i < VECTOR_LEN(_client->addresses); i++) {
			routemgr_probe_neighbor(&l3ctx.routemgr_ctx, _client->ifindex, &VECTOR_INDEX(_client->addresses, i).addr, _client->mac);
		}
	}

}

void rtnl_handle_neighbour(routemgr_ctx *ctx, const struct nlmsghdr *nh) {
	char ifname[IFNAMSIZ+1] = "";
	struct rtattr * tb[NDA_MAX+1];
	memset(tb, 0, sizeof(struct rtattr *) * (NDA_MAX + 1));
	char mac_str[18] = {};
	char ip_str[INET6_ADDRSTRLEN] = {};

	struct ndmsg *msg = NLMSG_DATA(nh);
	parse_rtattr(tb, NDA_MAX, NDA_RTA(msg), nh->nlmsg_len - NLMSG_LENGTH(sizeof(*msg)));

	if (tb[NDA_LLADDR]) {
		mac_addr_n2a(mac_str, RTA_DATA(tb[NDA_LLADDR]));
	}
	struct in6_addr dst_address = {};

	if (tb[NDA_DST]) {
		if (msg->ndm_family == AF_INET) {
			// form a transformed ipv6 address from the ipv4 address, we just parsed
			memcpy(&dst_address, &l3ctx.clientmgr_ctx.v4prefix,12);
			memcpy(&dst_address.s6_addr[12], RTA_DATA(tb[NDA_DST]), 4);
		}
		else
			memcpy(&dst_address, RTA_DATA(tb[NDA_DST]),16);

		inet_ntop(AF_INET6, &dst_address, ip_str, INET6_ADDRSTRLEN);
	}

	unsigned int br_index = if_nametoindex(ctx->client_bridge);

	if ( ctx->clientif_index == msg->ndm_ifindex || br_index == msg->ndm_ifindex ) {
		if (nh->nlmsg_type == RTM_NEWNEIGH && msg->ndm_state & NUD_REACHABLE && tb[NDA_LLADDR]) {
			if (l3ctx.debug)
				printf("Status-Change to NUD_REACHABLE, notifying change for client-mac [%s]\n",  mac_str) ;
			clientmgr_notify_mac(CTX(clientmgr), RTA_DATA(tb[NDA_LLADDR]), msg->ndm_ifindex);
		}

		if (l3ctx.debug) {
			if_indextoname(msg->ndm_ifindex, ifname);
			printf("neighbour [%s] (%s) changed on interface %s, type: %i, state: %i ... (msgif: %i cif: %i brif: %i)\n", mac_str, ip_str, ifname, nh->nlmsg_type, msg->ndm_state, msg->ndm_ifindex, ctx->clientif_index, br_index ); // see include/uapi/linux/neighbour.h NUD_REACHABLE for numeric values
		}

		if (msg->ndm_state & NUD_REACHABLE) {
			if (nh->nlmsg_type == RTM_NEWNEIGH && tb[NDA_DST] && tb[NDA_LLADDR]) {
				if (l3ctx.debug)
					printf("Status-Change to NUD_REACHABLE, ADDING address %s [%s]\n", ip_str, mac_str) ;
				clientmgr_add_address(CTX(clientmgr), &dst_address, RTA_DATA(tb[NDA_LLADDR]), msg->ndm_ifindex);
			}
		}
		else if (msg->ndm_state & NUD_FAILED) {
			if (nh->nlmsg_type == RTM_NEWNEIGH) {// TODO: re-try sending NS if no NA is received
				if (l3ctx.debug)
					printf("NEWNEIGH & NUD_FAILED received - sending NS for ip %s [%s]\n", ip_str, mac_str);
				icmp6_send_solicitation(CTX(icmp6), &dst_address); // we cannot replace this with our probe-function or we will endlessly loop between states.
			}
			else if (nh->nlmsg_type == RTM_DELNEIGH) {
				if (l3ctx.debug)
					printf("REMOVING (DELNEIGH) %s [%s]\n", ip_str, mac_str);
				rtmgr_client_remove_address(&dst_address);
			}
		}
		else if (msg->ndm_state & NUD_NOARP) {
			if (l3ctx.debug)
				printf("REMOVING (NOARP) %s [%s]\n", ip_str, mac_str);
			rtmgr_client_remove_address(&dst_address);
		}
	}
}

void rtnl_handle_link(routemgr_ctx *ctx, const struct nlmsghdr *nh) {
	const struct ifinfomsg *msg = NLMSG_DATA(nh);
	switch (nh->nlmsg_type) {
		case RTM_NEWLINK:
			printf("new link %i\n", msg->ifi_index);
			break;

		case RTM_SETLINK:
			printf("set link %i\n", msg->ifi_index);
			break;

		case RTM_DELLINK:
			printf("del link %i\n", msg->ifi_index);
			break;
	}

	interfaces_changed(nh->nlmsg_type, msg);
}

void handle_kernel_routes(routemgr_ctx *ctx, const struct nlmsghdr *nh) {
	int rc;

	struct kernel_route route;

	int len;

	struct rtmsg *rtm;

	len = nh->nlmsg_len;


	rtm = (struct rtmsg*)NLMSG_DATA(nh);
	len -= NLMSG_LENGTH(0);

	/* Ignore cached routes, advertised by some kernels (linux 3.x). */
	if (rtm->rtm_flags & RTM_F_CLONED)
		return;

	rc = parse_kernel_route_rta(rtm, len, &route);
	if (rc < 0)
		return;

	/* Ignore default unreachable routes; no idea where they come from. */
	if (route.plen == 0 && route.metric >= KERNEL_INFINITY)
		return;

	/* only interested in host routes */
	if (route.plen != 128)
		return;

	if (clientmgr_valid_address(&l3ctx.clientmgr_ctx, &route.prefix)) {
		if (nh->nlmsg_type == RTM_NEWROUTE)
			ipmgr_route_appeared(CTX(ipmgr), &route.prefix);
		else if (nh->nlmsg_type == RTM_DELROUTE) {
			printf("KERNEL ROUTE WAS REMOVED - TODO: SHOULD WE HANDLE THIS? ");
			print_ip(&route.prefix, "\n");
			struct client *_client = NULL;
			if (clientmgr_is_known_address(&l3ctx.clientmgr_ctx, &route.prefix, &_client)) {
				printf("   the route is for one of our clients\n");
				//if (client_is_active(&l3ctx.clientmgr_ctx, _client))
				//	printf("      The client is active\n");
				//				struct *client_ip *ip = get_client_ip(struct client *client, const struct in6_addr *address) {
				//client_ip_set_state(&l3ctx.clientmgr_ctx, struct client *client, struct client_ip *ip, IP_INACTIVE);
			}
		}
	}
}

void rtnl_handle_msg(routemgr_ctx *ctx, const struct nlmsghdr *nh) {
	switch (nh->nlmsg_type) {
		case RTM_NEWROUTE:
		case RTM_DELROUTE:
			handle_kernel_routes(ctx, nh);
			break;
		case RTM_NEWNEIGH:
		case RTM_DELNEIGH:
			rtnl_handle_neighbour(ctx, nh);
			break;
		case RTM_NEWLINK:
		case RTM_DELLINK:
		case RTM_SETLINK:
			rtnl_handle_link(ctx, nh);
			break;
		default:
			return;
	}
}

/* obtain all neighbours by sending GETNEIGH request
**/
static void routemgr_initial_neighbours(routemgr_ctx *ctx, uint8_t family) {
	struct nlneighreq req = {
		.nl = {
			.nlmsg_type = RTM_GETNEIGH,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
		},
		.nd = {
			.ndm_family = family,
		}

	};
	rtmgr_rtnl_talk(ctx, (struct nlmsghdr *)&req);
}

void routemgr_destroy(routemgr_ctx *ctx) {
	// TODO: remove all routes here
	close(ctx->fd);
}

void routemgr_init(routemgr_ctx *ctx) {
	printf("initializing routemgr\n");
	ctx->fd = socket(AF_NETLINK, SOCK_RAW|SOCK_NONBLOCK, NETLINK_ROUTE);
	if (ctx->fd < 0)
		exit_error("can't open RTNL socket");

	struct sockaddr_nl snl = {
		.nl_family = AF_NETLINK,
		.nl_groups = RTMGRP_IPV6_ROUTE | RTMGRP_LINK | RTMGRP_NEIGH,
	};

	if (bind(ctx->fd, (struct sockaddr *)&snl, sizeof(snl)) < 0)
		exit_error("can't bind RTNL socket");

	for (int i=0;i<VECTOR_LEN(CTX(clientmgr)->prefixes);i++) {
		char str[INET6_ADDRSTRLEN+1];
		struct prefix *prefix = &(VECTOR_INDEX(CTX(clientmgr)->prefixes, i));
		inet_ntop(AF_INET6, prefix->prefix.s6_addr, str, INET6_ADDRSTRLEN);
		printf("Activating route for prefix %s/%i on device %s(%i) in main routing-table\n", str, prefix->plen, CTX(ipmgr)->ifname, if_nametoindex(CTX(ipmgr)->ifname));

		routemgr_insert_route(ctx, 254, if_nametoindex(CTX(ipmgr)->ifname), (struct in6_addr*)(prefix->prefix.s6_addr), prefix->plen );
	}

	ctx->clientif_index = if_nametoindex(ctx->clientif);
	if (!ctx->clientif_index) {
		fprintf(stderr, "warning: we were started without -i - not initializing any client interfaces.\n");
		return;
	}
	routemgr_initial_neighbours(ctx, AF_INET);
	routemgr_initial_neighbours(ctx, AF_INET6);
}


int parse_kernel_route_rta(struct rtmsg *rtm, int len, struct kernel_route *route) {
	len -= NLMSG_ALIGN(sizeof(*rtm));

	memset(route, 0, sizeof(struct kernel_route));
	route->proto = rtm->rtm_protocol;

	for (struct rtattr *rta = RTM_RTA(rtm); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		switch(rta->rta_type) {
			case RTA_DST:
				route->plen = rtm->rtm_dst_len;
				memcpy(route->prefix.s6_addr, RTA_DATA(rta), 16);
				break;
			case RTA_SRC:
				route->src_plen = rtm->rtm_src_len;
				memcpy(route->src_prefix.s6_addr, RTA_DATA(rta), 16);
				break;
			case RTA_GATEWAY:
				memcpy(route->gw.s6_addr, RTA_DATA(rta), 16);
				break;
			case RTA_OIF:
				route->ifindex = *(int*)RTA_DATA(rta);
				break;
			case RTA_PRIORITY:
				route->metric = *(int*)RTA_DATA(rta);
				if(route->metric < 0 || route->metric > KERNEL_INFINITY)
					route->metric = KERNEL_INFINITY;
				break;
			default:
				break;
		}
	}

	return 1;
}

void routemgr_handle_in(routemgr_ctx *ctx, int fd) {
	while (1) {
		ssize_t count;
		uint8_t buf[8192];

		count = recv(fd, buf, sizeof buf, 0);
		if (count == -1) {
			if (errno != EAGAIN)
				perror("read");
			break;
		} else if (count == 0)
			break;

		const struct nlmsghdr *nh;
		struct nlmsgerr *ne;
		for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, count); nh = NLMSG_NEXT(nh, count)) {
			switch (nh->nlmsg_type) {
				case NLMSG_DONE:
					return;
				case NLMSG_ERROR:
					ne = NLMSG_DATA(nh);
					if (ne->error <= 0 )
						return; // from netlink(7): negative errno or 0 for acknoledgement
					perror("handling netlink error-message");
				default:
					rtnl_handle_msg(ctx, nh);
			}
		}
	}
}

int rtnl_addattr(struct nlmsghdr *n, int maxlen, int type, void *data, int datalen) {
	int len = RTA_LENGTH(datalen);
	struct rtattr *rta;
	if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen)
		return -1;
	rta = (struct rtattr*)(((char*)n) + NLMSG_ALIGN(n->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, datalen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;
	return 0;
}

void rtnl_add_address(routemgr_ctx *ctx, struct in6_addr *address) {
	rtnl_change_address(ctx, address, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL | NLM_F_REQUEST);
}

void rtnl_remove_address(routemgr_ctx *ctx, struct in6_addr *address) {
	rtnl_change_address(ctx, address, RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK);
}

void rtnl_change_address(routemgr_ctx *ctx, struct in6_addr *address, int type, int flags) {
	struct {
		struct nlmsghdr nl;
		struct ifaddrmsg ifa;
		char buf[1024];
	} req = {
		.nl = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
			.nlmsg_type = type,
			.nlmsg_flags = flags,
		},
		.ifa = {
			.ifa_family = AF_INET6,
			.ifa_prefixlen = 128,
			.ifa_index = 1, // get the loopback index
			.ifa_scope = 0,
		}
	};

	rtnl_addattr(&req.nl, sizeof(req), IFA_LOCAL, address, sizeof(struct in6_addr));

	rtmgr_rtnl_talk(ctx, (struct nlmsghdr*)&req);
}

void routemgr_probe_neighbor(routemgr_ctx *ctx, const int ifindex, struct in6_addr *address, uint8_t mac[6]) {
	int family = AF_INET6;
	size_t addr_len = 16;
	void *addr = address->s6_addr;

	if (clientmgr_is_ipv4(CTX(clientmgr), address)) {
		if (l3ctx.debug) {
			printf("probing for IPv4-address! ");
			print_ip((struct in6_addr*)addr, "\n");
		}
		addr = address->s6_addr + 12;
		addr_len = 4;
		family = AF_INET;
	} else {
		if (l3ctx.debug) {
			printf("probing for IPv6-address! ");
			print_ip((struct in6_addr*)address, "\n");
		}
	}

	struct nlneighreq req = {
		.nl = {
			.nlmsg_type = RTM_NEWNEIGH,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
		},
		.nd = {
			.ndm_family = family,
			.ndm_state = NUD_PROBE,
			.ndm_ifindex = ifindex,
		},
	};

	rtnl_addattr(&req.nl, sizeof(req), NDA_DST, (void*)addr, addr_len);
	rtnl_addattr(&req.nl, sizeof(req), NDA_LLADDR, mac, sizeof(uint8_t) * 6);

	rtmgr_rtnl_talk(ctx, (struct nlmsghdr*)&req);
}

void routemgr_insert_neighbor(routemgr_ctx *ctx, const int ifindex, struct in6_addr *address, uint8_t mac[6]) {
	struct nlneighreq req = {
		.nl = {
			.nlmsg_type = RTM_NEWNEIGH,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
		},
		.nd = {
			.ndm_family = AF_INET6,
			.ndm_state = NUD_REACHABLE,
			.ndm_ifindex = ifindex,
		},
	};

	rtnl_addattr(&req.nl, sizeof(req), NDA_DST, (void*)address, sizeof(struct in6_addr));
	rtnl_addattr(&req.nl, sizeof(req), NDA_LLADDR, mac, sizeof(uint8_t) * 6);

	rtmgr_rtnl_talk(ctx, (struct nlmsghdr*)&req);
}


void routemgr_remove_neighbor(routemgr_ctx *ctx, const int ifindex, struct in6_addr *address, uint8_t mac[6]) {
	struct nlneighreq req = {
		.nl = {
			.nlmsg_type = RTM_DELNEIGH,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE,
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
		},
		.nd = {
			.ndm_family = AF_INET6,
			.ndm_ifindex = ifindex,
			.ndm_flags = NTF_PROXY
		},
	};

	rtnl_addattr(&req.nl, sizeof(req), NDA_DST, (void*)address, sizeof(struct in6_addr));
	rtnl_addattr(&req.nl, sizeof(req), NDA_LLADDR, mac, sizeof(uint8_t) * 6);

	rtmgr_rtnl_talk(ctx, (struct nlmsghdr*)&req);
}

void routemgr_insert_route(routemgr_ctx *ctx, const int table, const int ifindex, struct in6_addr *address, const int prefix_length) {
	struct nlrtreq req = {
		.nl = {
			.nlmsg_type = RTM_NEWROUTE,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
		},
		.rt = {
			.rtm_family = AF_INET6,
			.rtm_table = table,
			.rtm_protocol = ROUTE_PROTO,
			.rtm_scope = RT_SCOPE_UNIVERSE,
			.rtm_type = RTN_UNICAST,
			.rtm_dst_len = prefix_length
		},
	};

	rtnl_addattr(&req.nl, sizeof(req), RTA_DST, (void*)address, sizeof(struct in6_addr));
	rtnl_addattr(&req.nl, sizeof(req), RTA_OIF, (void*)&ifindex, sizeof(ifindex));

	rtmgr_rtnl_talk(ctx, (struct nlmsghdr *)&req);
}

void routemgr_remove_route(routemgr_ctx *ctx, const int table, struct in6_addr *address, const int prefix_length) {
	struct nlrtreq req1 = {
		.nl = {
			.nlmsg_type = RTM_NEWROUTE,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
		},
		.rt = {
			.rtm_family = AF_INET6,
			.rtm_table = table,
			.rtm_type = RTN_THROW,
			.rtm_dst_len = prefix_length
		}
	};

	rtnl_addattr(&req1.nl, sizeof(req1), RTA_DST, (void*)address, sizeof(struct in6_addr));
	rtmgr_rtnl_talk(ctx, (struct nlmsghdr *)&req1);

	struct nlrtreq req2 = {
		.nl = {
			.nlmsg_type = RTM_DELROUTE,
			.nlmsg_flags = NLM_F_REQUEST,
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
		},
		.rt = {
			.rtm_family = AF_INET6,
			.rtm_table = table,
			.rtm_dst_len = 128
		}
	};

	rtnl_addattr(&req2.nl, sizeof(req2), RTA_DST, (void*)address, sizeof(struct in6_addr));
	rtmgr_rtnl_talk(ctx, (struct nlmsghdr *)&req2);
}

void rtmgr_rtnl_talk(routemgr_ctx *ctx, struct nlmsghdr *req) {
	struct sockaddr_nl nladdr = {
		.nl_family = AF_NETLINK
	};

	struct iovec iov = {req, 0};
	struct msghdr msg = {&nladdr, sizeof(nladdr), &iov, 1, NULL, 0, 0};

	iov.iov_len = req->nlmsg_len;

	int count=0;
	while (sendmsg(ctx->fd, &msg, 0) <= 0 && count < 5) {
		fprintf(stderr, "retrying(%i/5) ", ++count);
		perror("sendmsg on rtmgr_rtnl_talk()");
	}
}

void routemgr_insert_neighbor4(routemgr_ctx *ctx, const int ifindex, struct in_addr *address, uint8_t mac[6]) {
	struct nlneighreq req = {
		.nl = {
			.nlmsg_type = RTM_NEWNEIGH,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
		},
		.nd = {
			.ndm_family = AF_INET,
			.ndm_state = NUD_REACHABLE,
			.ndm_ifindex = ifindex,
		},
	};

	rtnl_addattr(&req.nl, sizeof(req), NDA_DST, (void*)address, sizeof(struct in_addr));
	rtnl_addattr(&req.nl, sizeof(req), NDA_LLADDR, mac, sizeof(uint8_t) * 6);

	rtmgr_rtnl_talk(ctx, (struct nlmsghdr*)&req);
}

void routemgr_remove_neighbor4(routemgr_ctx *ctx, const int ifindex, struct in_addr *address, uint8_t mac[6]) {
	struct nlneighreq req = {
		.nl = {
			.nlmsg_type = RTM_NEWNEIGH,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
		},
		.nd = {
			.ndm_family = AF_INET,
			.ndm_state = NUD_NONE,
			.ndm_ifindex = ifindex,
		},
	};

	rtnl_addattr(&req.nl, sizeof(req), NDA_DST, (void*)address, sizeof(struct in_addr));
	rtnl_addattr(&req.nl, sizeof(req), NDA_LLADDR, mac, sizeof(uint8_t) * 6);

	rtmgr_rtnl_talk(ctx, (struct nlmsghdr*)&req);
}

void routemgr_insert_route4(routemgr_ctx *ctx, const int table, const int ifindex, struct in_addr *address) {
	struct nlrtreq req = {
		.nl = {
			.nlmsg_type = RTM_NEWROUTE,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
		},
		.rt = {
			.rtm_family = AF_INET6,
			.rtm_table = table,
			.rtm_protocol = ROUTE_PROTO,
			.rtm_scope = RT_SCOPE_UNIVERSE,
			.rtm_type = RTN_UNICAST,
			.rtm_dst_len = 32
		},
	};

	rtnl_addattr(&req.nl, sizeof(req), RTA_DST, (void*)address, sizeof(struct in_addr));
	rtnl_addattr(&req.nl, sizeof(req), RTA_OIF, (void*)&ifindex, sizeof(ifindex));

	rtmgr_rtnl_talk(ctx, (struct nlmsghdr *)&req);
}

void routemgr_remove_route4(routemgr_ctx *ctx, const int table, struct in_addr *address) {
	struct nlrtreq req1 = {
		.nl = {
			.nlmsg_type = RTM_NEWROUTE,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
		},
		.rt = {
			.rtm_family = AF_INET,
			.rtm_table = table,
			.rtm_type = RTN_THROW,
			.rtm_dst_len = 32
		}
	};

	rtnl_addattr(&req1.nl, sizeof(req1), RTA_DST, (void*)address, sizeof(struct in_addr));
	rtmgr_rtnl_talk(ctx, (struct nlmsghdr *)&req1);

	struct nlrtreq req2 = {
		.nl = {
			.nlmsg_type = RTM_DELROUTE,
			.nlmsg_flags = NLM_F_REQUEST,
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
		},
		.rt = {
			.rtm_family = AF_INET,
			.rtm_table = table,
			.rtm_dst_len = 32
		}
	};

	rtnl_addattr(&req2.nl, sizeof(req2), RTA_DST, (void*)address, sizeof(struct in_addr));
	rtmgr_rtnl_talk(ctx, (struct nlmsghdr *)&req2);
}
