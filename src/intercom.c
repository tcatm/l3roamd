#include "intercom.h"
#include "error.h"
#include "l3roamd.h"
#include "icmp6.h"

#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#define INTERCOM_PORT 5523
#define INTERCOM_GROUP "ff02::5523"
#define INTERCOM_MAX_RECENT 100

static void join_mcast(const int sock, const struct in6_addr addr, const char *iface) {
  struct ipv6_mreq mreq;

  mreq.ipv6mr_multiaddr = addr;
  mreq.ipv6mr_interface = if_nametoindex(iface);

  if (mreq.ipv6mr_interface == 0)
    goto error;

  if (setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == -1)
    goto error;

  return;

 error:
  fprintf(stderr, "Could not join multicast group on %s: ", iface);
  perror(NULL);
}

void intercom_init(struct l3ctx *ctx, const char *ifname) {
  ctx->intercomfd = socket(PF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);

  if (ctx->intercomfd < 0)
  exit_error("creating socket");

  struct sockaddr_in6 server_addr = {};

  server_addr.sin6_family = AF_INET6;
  server_addr.sin6_addr = in6addr_any;
  server_addr.sin6_port = htons(INTERCOM_PORT);

  struct in6_addr mgroup_addr;

  inet_pton(AF_INET6, INTERCOM_GROUP, &mgroup_addr);
  join_mcast(ctx->intercomfd, mgroup_addr, ifname);

  if (bind(ctx->intercomfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }

  intercom_ctx *intercom_ctx = malloc(sizeof(intercom_ctx));
  intercom_ctx->groupaddr = malloc(sizeof(struct sockaddr_in6));

  struct sockaddr_in6 groupaddr = {
    .sin6_family = AF_INET6,
    .sin6_addr = mgroup_addr,
    .sin6_port = htons(INTERCOM_PORT),
    .sin6_scope_id = if_nametoindex(ifname)
  };

  bzero(&intercom_ctx->recent_packets, sizeof(VECTOR(intercom_packet_hdr)));

  memcpy(intercom_ctx->groupaddr, &groupaddr, sizeof(struct sockaddr_in6));

  ctx->intercom_ctx = intercom_ctx;
}

void intercom_seek(struct l3ctx *ctx, const struct in6_addr *address) {
  intercom_packet_seek packet;

  uint32_t nonce = rand();

  packet.hdr = (intercom_packet_hdr) {
    .type = INTERCOM_SEEK,
    .nonce = nonce,
    .ttl = 255,
  };

  memcpy(&packet.address, address, 16);

  intercom_recently_seen_add(ctx->intercom_ctx, &packet.hdr);

  intercom_send_packet((intercom_ctx*)ctx->intercom_ctx, ctx->intercomfd, (uint8_t*)&packet, sizeof(packet));
}

void intercom_send_packet(intercom_ctx *ctx, int fd, uint8_t *packet, ssize_t packet_len) {
  printf("intercom send %i %zi\n", fd, packet_len);
  ssize_t rc = sendto(fd, packet, packet_len, 0, ctx->groupaddr, sizeof(struct sockaddr_in6));
  // TODO Rückgabewert testen!
  printf("rc %zi\n", rc);
}

bool intercom_recently_seen(intercom_ctx *ctx, intercom_packet_hdr *hdr) {
  for (int i = 0; i < VECTOR_LEN(ctx->recent_packets); i++) {
    intercom_packet_hdr *ref_hdr = &VECTOR_INDEX(ctx->recent_packets, i);

    if (ref_hdr->nonce == hdr->nonce && ref_hdr->type == hdr->type &&
        memcmp(ref_hdr->sender, hdr->sender, 16) == 0)
        return true;
  }
  return false;
}

void intercom_recently_seen_add(intercom_ctx *ctx, intercom_packet_hdr *hdr) {
  if (VECTOR_LEN(ctx->recent_packets) > INTERCOM_MAX_RECENT)
    VECTOR_DELETE(ctx->recent_packets, 0);

  VECTOR_ADD(ctx->recent_packets, *hdr);
}

void intercom_handle_seek(struct l3ctx *ctx, intercom_packet_seek *packet) {
  icmp6_send_solicitation(ctx, (const struct in6_addr *)packet->address);
}

void intercom_handle_packet(struct l3ctx *ctx, uint8_t *packet, ssize_t packet_len) {
  intercom_packet_hdr *hdr = (intercom_packet_hdr*) packet;

  if (hdr->type == INTERCOM_SEEK)
    intercom_handle_seek(ctx, (intercom_packet_seek*) packet);

  hdr->ttl--;

  if (hdr->ttl > 0) {
    if (!intercom_recently_seen((intercom_ctx*)ctx->intercom_ctx, hdr)) {
      printf("intercom: forwarding packet\n");
      intercom_send_packet((intercom_ctx*)ctx->intercom_ctx, ctx->intercomfd, packet, packet_len);
    }
  }

  intercom_recently_seen_add((intercom_ctx*)ctx->intercom_ctx, hdr);
}

void intercom_handle_in(struct l3ctx *ctx, int fd) {
  ssize_t count;
  uint8_t buf[1500];

  while (1) {
    count = read(fd, buf, sizeof buf);

    if (count == -1) {
      /* If errno == EAGAIN, that means we have read all
         data. So go back to the main loop. */
      if (errno != EAGAIN) {
        perror("read");
      }
      break;
    } else if (count == 0) {
      /* End of file. The remote has closed the
         connection. */
      break;
    }

    intercom_handle_packet(ctx, buf, count);
  }
}
