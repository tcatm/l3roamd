#include "routes.h"
#include "error.h"

void print_route(struct kernel_route *route) {
  char ifname[IFNAMSIZ];
  char addr_prefix[INET6_ADDRSTRLEN];
  char src_addr_prefix[INET6_ADDRSTRLEN];
  char addr_gw[INET6_ADDRSTRLEN];

  if(!inet_ntop(AF_INET6, route->prefix,
        addr_prefix, sizeof(addr_prefix)) ||
      !inet_ntop(AF_INET6,route->gw, addr_gw, sizeof(addr_gw)) ||
      !if_indextoname(route->ifindex, ifname)) {
    printf("Couldn't format kernel route for printing.\n");
    return;
  }

  if(route->src_plen >= 0) {
    if(!inet_ntop(AF_INET6, route->src_prefix,
          src_addr_prefix, sizeof(src_addr_prefix))) {
      printf("Couldn't format kernel route for printing.\n");
      return;
    }

    printf("route: dest: %s/%d gw: %s metric: %d if: %s (from: %s/%d)\n",
        addr_prefix, route->plen, addr_gw, route->metric, ifname,
        src_addr_prefix, route->src_plen);
    return;
}

  printf("kernel route: dest: %s/%d gw: %s metric: %d if: %s\n",
      addr_prefix, route->plen, addr_gw, route->metric, ifname);
}

void rtnl_handle_link(struct l3ctx *ctx, const struct nlmsghdr *nh) {
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

  interfaces_changed(ctx, nh->nlmsg_type, msg);
}

void filter_kernel_routes(struct l3ctx *ctx, const struct nlmsghdr *nh) {
  int rc;

  struct kernel_route *current_route;
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

  current_route = &route;

  rc = parse_kernel_route_rta(rtm, len, current_route);
  if (rc < 0)
    return;

  /* Ignore default unreachable routes; no idea where they come from. */
  if (current_route->plen == 0 && current_route->metric >= KERNEL_INFINITY)
    return;

  /* only interested in host routes */
  if (current_route->plen != 128)
    return;

  ipmgr_route_appeared(&ctx->ipmgr_ctx, (const struct in6_addr*)&current_route->prefix);
}

void rtnl_handle_msg(struct l3ctx *ctx, const struct nlmsghdr *nh) {
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

void rtnl_init(struct l3ctx *ctx) {
  ctx->rtnl_sock = socket(AF_NETLINK, SOCK_RAW|SOCK_NONBLOCK, NETLINK_ROUTE);
  if (ctx->rtnl_sock < 0)
    exit_error("can't open RTNL socket");

  struct sockaddr_nl snl = {
    .nl_family = AF_NETLINK,
    .nl_groups = RTMGRP_IPV6_ROUTE | RTMGRP_LINK,
  };

  if (bind(ctx->rtnl_sock, (struct sockaddr *)&snl, sizeof(snl)) < 0)
    exit_error("can't bind RTNL socket");
}


int parse_kernel_route_rta(struct rtmsg *rtm, int len, struct kernel_route *route) {
    struct rtattr *rta = RTM_RTA(rtm);

    len -= NLMSG_ALIGN(sizeof(*rtm));

    memset(route, 0, sizeof(struct kernel_route));
    route->proto = rtm->rtm_protocol;

    while(RTA_OK(rta, len)) {
        switch(rta->rta_type) {
        case RTA_DST:
            route->plen = rtm->rtm_dst_len;
            memcpy(route->prefix, RTA_DATA(rta), 16);
            break;
        case RTA_SRC:
            route->src_plen = rtm->rtm_src_len;
            memcpy(route->src_prefix, RTA_DATA(rta), 16);
            break;
        case RTA_GATEWAY:
            memcpy(route->gw, RTA_DATA(rta), 16);
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
        rta = RTA_NEXT(rta, len);
    }

    return 1;
}

void rtnl_handle_in(struct l3ctx *ctx, int fd) {
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

struct nlrtreq {
  struct nlmsghdr nl;
  struct rtmsg rt;
  char buf[1024];
};

struct nlneighreq {
  struct nlmsghdr nl;
  struct ndmsg nd;
  char buf[1024];
};

void route_insert(struct l3ctx *ctx, const struct kernel_route *route, uint8_t *mac) {
  struct nlrtreq req = {
    .nl = {
      .nlmsg_type = RTM_NEWROUTE,
      .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
      .nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
    },
    .rt = {
      .rtm_family = AF_INET6,
      .rtm_table = route->table,
      .rtm_protocol = 158,
      .rtm_scope = RT_SCOPE_UNIVERSE,
      .rtm_type = RTN_UNICAST,
    },
  };

  struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
  struct iovec iov = { &req, 0 };
  struct msghdr msg = { &nladdr, sizeof(nladdr), &iov, 1, NULL, 0, 0 };

  req.rt.rtm_dst_len = route->plen;
  rtnl_addattr(&req.nl, sizeof(req), RTA_DST, (void*)route->prefix, sizeof(struct in6_addr));
  rtnl_addattr(&req.nl, sizeof(req), RTA_OIF, (void*)&route->ifindex, sizeof(unsigned int));

  iov.iov_len = req.nl.nlmsg_len;

  if (sendmsg(ctx->rtnl_sock, &msg, 0) < 0)
    perror("nl_sendmsg");

  struct nlneighreq ndreq = {
    .nl = {
      .nlmsg_type = RTM_NEWNEIGH,
      .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
      .nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
    },
    .nd = {
      .ndm_family = AF_INET6,
      .ndm_state = NUD_REACHABLE,
      .ndm_ifindex = route->ifindex,
    },
  };

  nladdr = (struct sockaddr_nl) { .nl_family = AF_NETLINK };
  iov = (struct iovec)  { &ndreq, 0 };
  msg = (struct msghdr) { &nladdr, sizeof(nladdr), &iov, 1, NULL, 0, 0 };

  rtnl_addattr(&ndreq.nl, sizeof(ndreq), NDA_DST, (void*)route->prefix, sizeof(struct in6_addr));
  rtnl_addattr(&ndreq.nl, sizeof(ndreq), NDA_LLADDR, mac, sizeof(uint8_t) * 6);

  iov.iov_len = ndreq.nl.nlmsg_len;

  if (sendmsg(ctx->rtnl_sock, &msg, 0) < 0)
    perror("nl_sendmsg");
}

void route_remove(struct l3ctx *ctx, const struct kernel_route *route) {
  struct nlrtreq req;
  struct sockaddr_nl nladdr;
  struct iovec iov;
  struct msghdr msg;

  req = (struct nlrtreq) {};
  req.nl = (struct nlmsghdr) {
    .nlmsg_type = RTM_NEWROUTE,
    .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
    .nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
  };
  req.rt = (struct rtmsg) {
    .rtm_family = AF_INET6,
    .rtm_table = route->table,
    .rtm_type = RTN_THROW,
  };

  nladdr = (struct sockaddr_nl) { .nl_family = AF_NETLINK };
  iov = (struct iovec) { &req, 0 };
  msg = (struct msghdr) { &nladdr, sizeof(nladdr), &iov, 1, NULL, 0, 0 };

  req.rt.rtm_dst_len = route->plen;
  rtnl_addattr(&req.nl, sizeof(req), RTA_DST, (void*)route->prefix, sizeof(struct in6_addr));

  iov.iov_len = req.nl.nlmsg_len;

  if (sendmsg(ctx->rtnl_sock, &msg, 0) < 0)
    perror("nl_sendmsg");

  // TODO remove neighbour entry

  req = (struct nlrtreq) {};
  req.nl = (struct nlmsghdr) {
    .nlmsg_type = RTM_DELROUTE,
    .nlmsg_flags = NLM_F_REQUEST,
    .nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
  };
  req.rt = (struct rtmsg) {
    .rtm_family = AF_INET6,
    .rtm_table = route->table,
  };

  nladdr = (struct sockaddr_nl) { .nl_family = AF_NETLINK };
  iov = (struct iovec) { &req, 0 };
  msg = (struct msghdr) { &nladdr, sizeof(nladdr), &iov, 1, NULL, 0, 0 };

  req.rt.rtm_dst_len = route->plen;
  rtnl_addattr(&req.nl, sizeof(req), RTA_DST, (void*)route->prefix, sizeof(struct in6_addr));

  iov.iov_len = req.nl.nlmsg_len;

  if (sendmsg(ctx->rtnl_sock, &msg, 0) < 0)
    perror("nl_sendmsg");
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
