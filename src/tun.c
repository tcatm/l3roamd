#include "error.h"
#include "tun.h"

#include <fcntl.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_tun.h>

void tun_open(struct tun_iface *iface, const char *ifname, uint16_t mtu, const char *dev_name) {
  int ctl_sock = -1;
  struct ifreq ifr = {};

  iface->fd = open(dev_name, O_RDWR|O_NONBLOCK);
  if (iface->fd < 0)
    exit_errno("could not open TUN/TAP device file");

  if (ifname)
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

  if (ioctl(iface->fd, TUNSETIFF, &ifr) < 0) {
    puts("unable to open TUN/TAP interface: TUNSETIFF ioctl failed");
    goto error;
  }

  iface->name = strndup(ifr.ifr_name, IFNAMSIZ-1);

  ctl_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (ctl_sock < 0)
    exit_errno("socket");

  if (ioctl(ctl_sock, SIOCGIFMTU, &ifr) < 0)
    exit_errno("SIOCGIFMTU ioctl failed");

  if (ifr.ifr_mtu != mtu) {
    ifr.ifr_mtu = mtu;
    if (ioctl(ctl_sock, SIOCSIFMTU, &ifr) < 0) {
      puts("unable to set TUN/TAP interface MTU: SIOCSIFMTU ioctl failed");
      goto error;
    }
  }

  if (close(ctl_sock))
    puts("close");

  return;

error:
  if (ctl_sock >= 0) {
    if (close(ctl_sock))
      puts("close");
  }

  close(iface->fd);
  iface->fd = -1;
}

void tun_handle_in(struct l3ctx *ctx, int fd) {
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

    if (count < 40)
      continue;

    // We're only interested in ip6 packets
    if ((buf[0] & 0xf0) != 0x60)
      continue;

    handle_packet(ctx, buf, count);
  }
}

void tun_handle_out(struct l3ctx *ctx, int fd) {
  ssize_t count;
  while (1) {
    if (list_is_empty(&ctx->output_queue))
      break;

    struct packet *packet = list_shift(&ctx->output_queue);
    count = write(fd, packet->data, packet->len);

    free(packet->data);
    free(packet);

    if (count == -1) {
      if (errno != EAGAIN)
        perror("write");

      break;
    }
  }
}
