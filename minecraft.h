#ifndef __MINECRAFT_H
#define __MINECRAFT_H

#include "net/pkt.h"
#include "version.h"
#include <sys/types.h>

enum MC_REQ {
    MC_REQ_HANDSHAKE,
    MC_REQ_PING,
    MC_REQ_SPL,
    MC_REQ_LOGIN
};

enum MC_STATUS {
    MC_STATUS_HANDSHAKE    = 1,
    MC_STATUS_LOGIN        = 2,
    MC_STATUS_PLAY         = 3
};

struct serverinfo *mc_connect(const char *host, u_int16_t port, u_int32_t proto);
void mc_login(struct serverinfo *si, struct userinfo *ui);
void mc_getinfo(struct serverinfo *si, enum MC_REQ info);
void mc_eventloop(struct serverinfo *si);
void mc_cleanup(void *ptr);

#endif // __MINECRAFT_H
