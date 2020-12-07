#include "utils.h"
#include "minecraft.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

struct serverinfo *mc_connect(const char *host, uint16_t port, uint32_t proto) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);

  if (fd < 0) {
    fprintf(stderr, "Fail to create socket: %s", strerror(errno));
    return NULL;
  }

  struct sockaddr_in sin = {
      .sin_family = AF_INET,
      .sin_port = htons(port),
  };

  int ret;
  ret = inet_pton(AF_INET, host, &sin.sin_addr);
  if (ret != 1) {
    fprintf(stderr, "Not a vail address: %s", strerror(errno));
    return NULL;
  }

  ret = connect(fd, (struct sockaddr *)&sin, sizeof(struct sockaddr_in));
  if (ret != 0) {
    fprintf(stderr, "Fail to connect to host: %s", strerror(errno));
    return NULL;
  }

  struct serverinfo *si = malloc(sizeof(struct serverinfo));
    if (si == NULL) {
        fprintf(stderr, "Fail to malloc: %s", strerror(errno));
        return NULL;
    }

  memset(si, 0, sizeof(struct serverinfo));
  si->si_conninfo.sockfd = fd;
  si->si_conninfo.addr = host;
  si->si_conninfo.port = port;
  si->si_conninfo.proto = proto;
    return si;
}

void mc_getinfo(struct serverinfo *si, MCINFO info) {
   send_handshake(si, 1);

   switch (info) {
    case MCINFO_PING:
      uint64_t time = 0x123456789ABCDEF;
      send_ping(si, time);
      break;
    case MCINFO_SERVER_INFO:
      send_slp(si);
      break;
   }
}
void mc_login(struct serverinfo *si, struct userinfo *ui) {
   send_handshake(si, 2);
   // send_encryption(&si);
}