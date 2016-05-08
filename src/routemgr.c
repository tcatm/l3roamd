#include "routemgr.h"
#include "error.h"
#include "l3roamd.h"

static void rtnl_change_address(routemgr_ctx *ctx, struct in6_addr *address, int type, int flags);
static void rtnl_handle_link(routemgr_ctx *ctx, const struct nlmsghdr *nh);
static int rtnl_addattr(struct nlmsghdr *n, int maxlen, int type, void *data, int datalen);
static void rtnl_talk(routemgr_ctx *ctx, struct nlmsghdr *req);

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

  interfaces_changed(ctx->l3ctx, nh->nlmsg_type, msg);
}

void filter_kernel_routes(routemgr_ctx *ctx, const struct nlmsghdr *nh) {
  int rc;

  struct kernel_route route;

  int len;

  struct rtmsg *rtm;

  len = nh->nlmsg_len;

  if (nh->nlmsg_type != RTM_NEWROUTE)
    return;

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

  ipmgr_route_appeared(CTX(ipmgr), &route.prefix);
}

void rtnl_handle_msg(routemgr_ctx *ctx, const struct nlmsghdr *nh) {
  switch (nh->nlmsg_type) {
    case RTM_NEWROUTE:
    case RTM_DELROUTE:
      filter_kernel_routes(ctx, nh);
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

void routemgr_init(routemgr_ctx *ctx) {
  ctx->fd = socket(AF_NETLINK, SOCK_RAW|SOCK_NONBLOCK, NETLINK_ROUTE);
  if (ctx->fd < 0)
    exit_error("can't open RTNL socket");

  struct sockaddr_nl snl = {
    .nl_family = AF_NETLINK,
    .nl_groups = RTMGRP_IPV6_ROUTE | RTMGRP_LINK,
  };

  if (bind(ctx->fd, (struct sockaddr *)&snl, sizeof(snl)) < 0)
    exit_error("can't bind RTNL socket");
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
    for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, count); nh = NLMSG_NEXT(nh, count)) {
      switch (nh->nlmsg_type) {
        case NLMSG_DONE:
          return;
        case NLMSG_ERROR:
          perror("error: netlink error");
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
  rtnl_change_address(ctx, address, RTM_DELADDR, NLM_F_REQUEST);
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

  rtnl_talk(ctx, (struct nlmsghdr*)&req);
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

  rtnl_talk(ctx, (struct nlmsghdr*)&req);
}

void routemgr_remove_neighbor(routemgr_ctx *ctx, const int ifindex, struct in6_addr *address, uint8_t mac[6]) {
  struct nlneighreq req = {
    .nl = {
      .nlmsg_type = RTM_NEWNEIGH,
      .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
      .nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
    },
    .nd = {
      .ndm_family = AF_INET6,
      .ndm_state = NUD_NONE,
      .ndm_ifindex = ifindex,
    },
  };

  rtnl_addattr(&req.nl, sizeof(req), NDA_DST, (void*)address, sizeof(struct in6_addr));
  rtnl_addattr(&req.nl, sizeof(req), NDA_LLADDR, mac, sizeof(uint8_t) * 6);

  rtnl_talk(ctx, (struct nlmsghdr*)&req);
}

void routemgr_insert_route(routemgr_ctx *ctx, const int table, const int ifindex, struct in6_addr *address) {
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
      .rtm_dst_len = 128
    },
  };

  rtnl_addattr(&req.nl, sizeof(req), RTA_DST, (void*)address, sizeof(struct in6_addr));
  rtnl_addattr(&req.nl, sizeof(req), RTA_OIF, (void*)&ifindex, sizeof(ifindex));

  rtnl_talk(ctx, (struct nlmsghdr *)&req);
}

void routemgr_remove_route(routemgr_ctx *ctx, const int table, struct in6_addr *address) {
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
      .rtm_dst_len = 128
    }
  };

  rtnl_addattr(&req1.nl, sizeof(req1), RTA_DST, (void*)address, sizeof(struct in6_addr));
  rtnl_talk(ctx, (struct nlmsghdr *)&req1);

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
  rtnl_talk(ctx, (struct nlmsghdr *)&req2);
}

void rtnl_talk(routemgr_ctx *ctx, struct nlmsghdr *req) {
  struct sockaddr_nl nladdr = {
    .nl_family = AF_NETLINK
  };

  struct iovec iov = {req, 0};
  struct msghdr msg = {&nladdr, sizeof(nladdr), &iov, 1, NULL, 0, 0};

  iov.iov_len = req->nlmsg_len;

  if (sendmsg(ctx->fd, &msg, 0) < 0)
    perror("nl_sendmsg");
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

  rtnl_talk(ctx, (struct nlmsghdr*)&req);
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

  rtnl_talk(ctx, (struct nlmsghdr*)&req);
}

void routemgr_insert_route4(routemgr_ctx *ctx, const int table, const int ifindex, struct in_addr *address) {
  struct nlrtreq req = {
    .nl = {
      .nlmsg_type = RTM_NEWROUTE,
      .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
      .nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
    },
    .rt = {
      .rtm_family = AF_INET,
      .rtm_table = table,
      .rtm_protocol = ROUTE_PROTO,
      .rtm_scope = RT_SCOPE_UNIVERSE,
      .rtm_type = RTN_UNICAST,
      .rtm_dst_len = 32
    },
  };

  rtnl_addattr(&req.nl, sizeof(req), RTA_DST, (void*)address, sizeof(struct in_addr));
  rtnl_addattr(&req.nl, sizeof(req), RTA_OIF, (void*)&ifindex, sizeof(ifindex));

  rtnl_talk(ctx, (struct nlmsghdr *)&req);
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
  rtnl_talk(ctx, (struct nlmsghdr *)&req1);

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
  rtnl_talk(ctx, (struct nlmsghdr *)&req2);
}
