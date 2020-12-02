#ifndef __MC_TYPE_H
#define __MC_TYPE_H


#include <stdint.h>


typedef unsigned char byte;
typedef byte varint[5];
typedef byte varlong[10];

/* connection information struct */
// typedef struct conninfo_t {
//     varint proto;
//     char *addr[16];
//     uint16_t port;
// } conninfo_t;

/* server information struct */
// typedef struct serverinfo_t {
//     conninfo_t conn;
//     char servername[32];
//     char serverid[16];
//     uint16_t max_player;
//     uint16_t curr_player;
// } serverinfo_t;

// serverbound
/* stage1 */
#define MC_SLP 0x00
#define MC_PING 0x01

/* login_stage2 */
#define MC_LOGIN 0x00
#define MC_ENCRYPT 0x01


// clientbound
typedef struct _pong_t {
} pong_t;

typedef struct _encrypt_req_t {
    char e_srvid[20];
    varint e_publen;
} encrypt_req_t;

#endif // __MC_TYPE_H
