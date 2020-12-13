#ifndef __MC_PKT_H
#define __MC_PKT_H

#include "../minecraft.h"
#include "../crypto.h"
#include "../utils.h"
#include <sys/types.h>

enum M_REQ;

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
    M_PACKET_SET_DIFFICULT_C = 0x0D,
    M_PACKET_DECLARE_COMMAND = 0x10,
    M_PACKET_PLAYER_STATUS = 0x1A,
    M_PACKET_PLAYER_POSITION_AND_LOOK = 0x34,
    M_PACKET_UPDATE_VIEW_POSITION = 0x40,
    M_PACKET_KEEPALIVE_C = 0x1F,

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
    M_PACKET_SET_DIFFICULT_S = 0x02,
    M_PACKET_CHAT = 0x03,
    M_PACKET_KEEPALIVE_S = 0x10,
};

size_t build_handshake(struct buffer *buf, void *data);

/* Status */
size_t build_slp(struct buffer *buf, void *data);
size_t build_ping(struct buffer *buf, void *data);

/* Login */
size_t build_login(struct buffer *buf, void *data);
size_t build_encryption(struct buffer *buf, void *data);

/* Play */
size_t build_chat(struct buffer *buf, void *data);
size_t build_set_difficult(struct buffer *buf, void *data);
size_t build_keepalive(struct buffer *buf, void *data);

/* packet reader, sender */
ssize_t read_packet(struct serverinfo *si, struct userinfo *ui, void *userdata);
ssize_t send_packet(enum M_REQ type, struct serverinfo *si, struct userinfo *ui, void *data);

#endif // __MC_PKT_H
