#ifndef __MC_PKT_H
#define __MC_PKT_H

#include "../minecraft.h"
#include "type.h"
#include "../crypto.h"
#include <sys/types.h>

enum MC_REQ;

enum M_PACKET_CLIENTBOUND {
    /* Status (Handshake) */
    M_PACKET_SLPRESP = 0x00,
    M_PACKET_PONG = 0x01,

    /* Login */
    M_PACKET_DISCONNECT = 0x00,
    M_PACKET_ENCRYPTREQ = 0x01,
    M_PACKET_LOGINSUCCESS = 0x02,
    M_PACKET_SETCOMPRESSION = 0x03,

    /* Play */
    M_PACKET_KEEPALIVE = 0x1F,

};

enum M_PACKET_SERVERBOUND {
    M_PACKET_HANDSHAKE = 0x00,

    /* Status (Handshake) */
    M_PACKET_SLPREQ = 0x00,
    M_PACKET_PING = 0x01,

    /* Login */
    M_PACKET_LOGIN = 0x00,
    M_PACKET_ENCRYPTRES = 0x01,

    /* Play */
    M_PACKET_SET_DIFFICULT = 0x02,
    M_PACKET_CHAT = 0x03,
};

size_t build_handshake(struct buffer *buf, void *data);
size_t build_slp(struct buffer *buf, void *data);
size_t build_ping(struct buffer *buf, void *data);
size_t build_login(struct buffer *buf, void *data);
size_t build_chat(struct buffer *buf, void *data);
size_t build_set_difficult(struct buffer *buf, void *data);
size_t build_encryption(struct buffer *buf, void *data);

ssize_t read_packet(struct serverinfo *si, struct userinfo *ui, void *userdata);
ssize_t send_packet(enum MC_REQ type, struct serverinfo *si, struct userinfo *ui, void *data);

#endif // __MC_PKT_H
