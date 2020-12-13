#ifndef __MINECRAFT_H
#define __MINECRAFT_H

#include "crypto.h"
#include "version.h"
#include "net/pkt.h"
#include <sys/types.h>

enum M_ERR {
    M_ERR_MEMORY,      /* if fail to alloc memory */
    M_ERR_SECRETKEY,   /* if fail to generate secret key */
    M_ERR_PUBKEY,      /* if fail to parse public key secret key */
    M_ERR_ENCRYPT,     /* if fail to encrypt data */
    M_ERR_DECRYPT,     /* if fail to decrypt data */
    M_ERR_DEFLAT,      /* if fail to compress packet */
    M_ERR_INFLAT,      /* if fail to uncompress packet */
    M_ERR_DATA,        /* if fail to read socket */
    M_ERR_DIGEST,      /* if fail to generate digest */
};

typedef struct mc_message {
    int type;

} mc_message_t;

enum M_REQ {
    M_REQ_HANDSHAKE,
    /* Status (Handshake) */
    M_REQ_SPL,
    M_REQ_PING,

    /* Login */
    M_REQ_LOGIN,
    M_REQ_ENCRYPTRES,

    /* Play */
    M_REQ_CHAT,
    M_REQ_SET_DIFFICULT,
    M_REQ_KEEPALIVE,
};

enum M_STATE {
    M_STATE_HANDSHAKE = 1,
    M_STATE_LOGIN = 2,
    M_STATE_PLAY = 3
};

typedef struct conninfo {
    int sockfd;
    uint32_t proto;
    const char *addr;
    uint16_t port;
    int32_t state;
    uint32_t thresh;
    long keepalive;
} conninfo_t;

typedef struct encrypt {
    struct buffer *e_id;
    struct buffer *e_pubkey;
    struct buffer *e_verify;
    struct buffer *e_secret;
    EVP_CIPHER_CTX *e_encctx;
    EVP_CIPHER_CTX *e_decctx;
} encrypt_t;

typedef struct serverinfo {
    struct conninfo si_conninfo;
    struct encrypt *si_encinfo;
} serverinfo_t;

typedef struct userinfo {
    char ui_name[16];
    char ui_token[24];
    char ui_uuid[24];
} userinfo_t;

struct serverinfo *mc_connect(const char *host, u_int16_t port, u_int32_t proto);
void mc_login(struct serverinfo *si, struct userinfo *ui);
void mc_getinfo(struct serverinfo *si, enum M_REQ info);
void mc_set_difficult(struct serverinfo *si, int32_t level);
void mc_chat(struct serverinfo *si, const char *msg);
void mc_init_cipher(struct serverinfo *si);
void mc_eventloop(struct serverinfo *si);
void mc_wait_until_login_success(struct serverinfo *si);
void mc_cleanup(struct serverinfo *si);
char *mc_err_getstr(enum M_ERR err);

#endif // __MINECRAFT_H
