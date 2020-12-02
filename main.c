#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

// #include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "version.h"
#include "net/type.h"
#include "net/pkt.h"

void dump(void *buf, int n) {
  char *_buf = buf;
  while (n-- > 0)
    printf("%x ", (*_buf++) & 0xff);
  printf("\n");
}

ssize_t send_handshake(int fd, handshake_t *data) {
  char *buf = (char *)malloc(1024);
  char *pbuf = buf + 5;
  varint vint;

  *pbuf++ = data->id; // handshake packet type
  pbuf = serialize_varint(pbuf, (char *)data->protocol);
  pbuf = serialize_str(pbuf, data->addr);
  pbuf = serialize_short(pbuf, data->port);
  pbuf = serialize_varint(pbuf, data->state);

  int size = pbuf - (buf + 5);

  size_t n = to_varint(size, &vint);

  pbuf = buf + 5 - n; // fill reserved varint for length
  serialize_varint(pbuf, vint);

  n = write(fd, pbuf, n + size);
  free(buf);
  return n;
}

int main(int argc, char *argv[]) {

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  int ret;

  if (fd < 0) {
    perror("socket()");
    exit(1);
  }

  struct sockaddr_in sin = {
      .sin_family = AF_INET,
      .sin_port = htons(25565),
  };

  inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr);
  ret = connect(fd, (struct sockaddr *)&sin, sizeof(struct sockaddr_in));

  if (ret != 0) {
    perror("connect()");
    exit(1);
  }

  varint out;
  to_varint(2222222, &out);
  handshake_t hand = {.id = 0x00,
                      .protocol = &out,
                      .addr = "127.0.0.1",
                      .port = 25565,
                      .state = 1};

  ret = send_handshake(fd, &hand);
  printf("write %d bytes!\n", ret);

  char s[2] = {1, 0};
  write(fd, s, 2);

  byte buf[1024];
  ssize_t nr = read(fd, buf, 1024);
  int len;
  nr = deserialize_verint(buf, &len);
  printf("size: %d\n", len);
  dump(buf, len);

  return 0;
}
