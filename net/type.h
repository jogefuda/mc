#ifndef __MC_TYPE_H
#define __MC_TYPE_H

typedef unsigned char byte;
typedef byte varint[5];
typedef byte varlong[10];

typedef struct __handshake_packet_t {
  unsigned char id;
  const varint *protocol;
  const char *addr;
  unsigned short port;
  const varint state;
} handshake_t;

#endif // __MC_TYPE_H
