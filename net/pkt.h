#ifndef __MC_PKT_H
#define __MC_PKT_H

#include "type.h"
#include "../crypto.h"
#include <sys/types.h>

/*
// packet struct
*/
typedef struct conninfo {
    int sockfd;
    uint32_t proto;
    char *addr;
    uint16_t port;
    int32_t state;
} conninfo_t;

typedef struct encrypt {
    struct bytearray e_pubkey;
    struct bytearray e_verify;
    struct bytearray e_presharekey;
} encrypt_t;

typedef struct serverinfo {
    char id[20];
    struct conninfo si_conninfo;
    struct encrypt si_encinfo;
} serverinfo_t;

typedef struct userinfo {
    char ui_name[16];
} userinfo_t;


////////////////////
// handshaking structure
////////////////////
/* Get server information include Name, icon, max player, current player */
typedef struct slp {
  char data[1];
} slp_t;

/* server return same as data */
typedef struct ping {
  uint64_t data;
} ping_t;

/* handshake with server 
if state == 1 handshaking state
if state == 2 long state
*/
typedef struct handshake {
  char *addr;
  uint16_t port;
  uint32_t state;
} handshake_t;

ssize_t send_handshake(struct serverinfo *si, int state);
ssize_t send_slp(struct serverinfo *si);
ssize_t send_ping(struct serverinfo *si, long data);
ssize_t send_login(struct serverinfo *si, struct userinfo *ui);

ssize_t read_response(struct serverinfo *si, struct userinfo *ui, void *userdata);


/* */
#define MS_HANDSHAKING 0x01
#define MS_LOGIN 0x02

/* server bound */
/* status.1 handshaking */
#define MP_HANDSHAKING 0x00
#define MP_SLP 0x00
#define MP_PING 0x01

/* status.2 login */
#define MP_LOGIN 0x00

/* client bound */
#define MP_SLP_RES 0x00
#define MP_PONG_RES 0x01
#define MP_ENCRYPT_REQ 0x01
#endif // __MC_PKT_H
