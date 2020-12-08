#ifndef __MC_PKT_H
#define __MC_PKT_H

#include "../minecraft.h"
#include "type.h"
#include "../crypto.h"
#include <sys/types.h>

enum MC_REQ;

/*
// packet struct
*/
typedef struct conninfo {
    int sockfd;
    uint32_t proto;
    const char *addr;
    uint16_t port;
    int32_t state;
    int32_t compressed;
} conninfo_t;

typedef struct encrypt {
    struct bytearray e_pubkey;
    struct bytearray e_verify;
    struct bytearray e_secret;
} encrypt_t;

typedef struct serverinfo {
    char id[20];
    struct conninfo si_conninfo;
    struct encrypt si_encinfo;
} serverinfo_t;

typedef struct userinfo {
    char ui_name[16];
    char ui_token[24];
    char ui_uuid[24];
} userinfo_t;

enum M_PACKET_CLIENTBOUND {
  M_PACKET_PONG,
  M_PACKET_ENCRYPT,
  M_PACKET_SETCOMPRESS
} ;

enum M_PACKET_SERVERBOUND {
  M_PACKET_HANDSHAKE   = 0x00,
  M_PACKET_SERVER_LIST = 0x00,
  M_PACKET_PING        = 0x01,
  M_PACKET_LOGIN       = 0x00,
  M_PACKET_CHAT        = 0x01,
};

size_t build_handshake(struct buffer *buf, void *data);
size_t build_slp      (struct buffer *buf, void *data);
size_t build_ping     (struct buffer *buf, void *data);
size_t build_login    (struct buffer *buf, void *data);
size_t build_chat     (struct buffer *buf, void *data);

ssize_t read_packet(struct serverinfo *si, struct userinfo *ui, void *userdata);
ssize_t send_packet(enum MC_REQ type, struct serverinfo *si, struct userinfo *ui, void *data);

#endif // __MC_PKT_H
