#include "pkt.h"
#include "../crypto.h"
#include "../utils.h"
#include "../compress.h"
#include "serialize.h"
#include "auth.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

// parse packet
void parse_setcompression(struct serverinfo *si, struct buffer *buf) {
    int32_t thresh;
    deserialize_varint(buf, &thresh);
    si->si_conninfo.thresh = thresh;
}

void parse_loginsuccess(struct serverinfo *si, struct buffer *buf) {
    si->si_conninfo.state = MC_STATUS_PLAY;
    // TODO: parse uuid string (16) 
    //             name string
}

void parse_keepalive(struct serverinfo *si, struct buffer *buf) {
    deserialize_long(buf, &si->si_conninfo.keepalive);
    puts("KEEPALIVE REQUIRE\n");
}

void parse_encryptreq(struct serverinfo *si, struct buffer *buf) {
    si->si_encinfo->e_id = new_buffer(10);
    si->si_encinfo->e_secret = new_buffer(16);
    si->si_encinfo->e_pubkey = new_buffer(128);
    si->si_encinfo->e_verify = new_buffer(128);
    if (!si->si_encinfo->e_id || !si->si_encinfo->e_pubkey || !si->si_encinfo->e_verify) {
        // TODO: error handle
    }

    deserialize_str(buf, si->si_encinfo->e_id);
    deserialize_str(buf, si->si_encinfo->e_pubkey);
    deserialize_str(buf, si->si_encinfo->e_verify);

    send_packet(MC_REQ_ENCRYPTRES, si, NULL, NULL);
}

//
ssize_t read_packet(struct serverinfo *si, struct userinfo *ui, void *userdata) {
    int fd = si->si_conninfo.sockfd;
    int compress_enabled = si->si_conninfo.thresh > 0;
    int encrypt_enabled = si->si_encinfo->e_decctx;
    EVP_CIPHER_CTX *cipher = si->si_encinfo->e_decctx;
    int state = si->si_conninfo.state;
    int ret;
    struct buffer *buf, *out;
    int32_t pktlen, uncompressed_pktlen, pkttype;
    size_t nbytes, remain_pktbytes;

    fread_varint(fd, &pktlen, cipher);
    buf = new_buffer(pktlen);
    if (buf == NULL) {
        // TODO: error handle
    }
    // TODO: change initial buffer size
    nbytes = 0;
    if (compress_enabled)
        nbytes += fread_varint(fd, &uncompressed_pktlen, cipher);

    remain_pktbytes = (compress_enabled) ? pktlen - nbytes : pktlen;

    if ((ret = read(fd, buf->b_data, remain_pktbytes)) < 1) {
        // TODO: error handle
        printf("ERROR=================\n");
    }
    // printf("read: %d\n", ret);
    buf->b_size = ret;

    if (compress_enabled && uncompressed_pktlen > 0) {
        // TODO: error handle
        out = new_buffer(buf->b_size);
        ret = mc_inflat_pkt(buf, out);
        del_buffer(buf);
        buf = out;
        out = NULL;
    }

    if (encrypt_enabled)
        aes_cipher_update(cipher, buf, buf);
    deserialize_varint(buf, &pkttype);
    // TODO: 1. impl state 1 and 2
    //       2. is proccessed variable
    if (state == MC_STATUS_PLAY) {
        switch (pkttype) {
            case M_PACKET_KEEPALIVE:
                parse_keepalive(si, buf);
                break;
        }
    } else if (state == MC_STATUS_LOGIN) {
        switch (pkttype) {
            case M_PACKET_LOGINSUCCESS:
                parse_loginsuccess(si, buf);
                break;
            case M_PACKET_ENCRYPTREQ:
                parse_encryptreq(si, buf);
                break;
            case M_PACKET_SETCOMPRESSION:
                parse_setcompression(si, buf);
                break;
                // consume broken packet
        }
    }
    // buf->b_next = buf->b_data;
    // dump(buf->b_data, buf->b_size);
    printf("pkgsize: %d, 0x%x\n", pktlen, pkttype);

    del_buffer(buf);
    return 0;
}

ssize_t send_packet(enum MC_REQ type, struct serverinfo *si, struct userinfo *ui, void *data) {
    struct buffer *buf, *zbuf, *header;
    header = new_buffer(10);
    buf = new_buffer(128);
    int compress_enabled = si->si_conninfo.thresh > 0;
    int encrypt_enabled = si->si_encinfo->e_encctx;
    int fd = si->si_conninfo.sockfd;
    int state = si->si_conninfo.state;

    size_t pktsize;
    switch (type) {
        case MC_REQ_HANDSHAKE:
            pktsize = build_handshake(buf, si); break;
        case MC_REQ_PING:
            pktsize = build_ping(buf, data); break;
        case MC_REQ_SPL:
            pktsize = build_slp(buf, NULL); break;
        case MC_REQ_LOGIN:
            pktsize = build_login(buf, ui); break;
        case MC_REQ_ENCRYPTRES:
            pktsize = build_encryption(buf, si);

            // TODO: change to event based.
            mc_auth(si, NULL);
            mc_init_cipher(si);
            break;
        case MC_REQ_CHAT:
            pktsize = build_chat(buf, data); break;
        case MC_REQ_SET_DIFFICULT:
            pktsize = build_set_difficult(buf, data); break;
    }

    if (compress_enabled) {
        if (buf->b_size > si->si_conninfo.thresh) {
            zbuf = new_buffer(buf->b_allocsize * 0.8);
            if (zbuf == NULL) {
                // TODO: error handle
            }
            mc_deflat_pkt(buf, zbuf);
            del_buffer(buf);
            buf = zbuf;
            serialize_varint(header, pktsize + get_varint_len(pktsize));
            serialize_varint(header, pktsize);
        } else {
            serialize_varint(header, pktsize + get_varint_len(0));
            serialize_varint(header, 0);
        }
    } else {
        serialize_varint(header, pktsize);
    }

    if (encrypt_enabled) {
        aes_cipher_update(si->si_encinfo->e_encctx, header, header);
        aes_cipher_update(si->si_encinfo->e_encctx, buf, buf);
    }

    write(fd, header->b_data, header->b_size);
    write(fd, buf->b_data, buf->b_size);

    del_buffer(header);
    del_buffer(buf);
    return 1;
}

size_t build_handshake(struct buffer *buf, void *data) {
    struct serverinfo *si = (struct serverinfo *)data;
    size_t pkgsize = 0;
    pkgsize += serialize_varint(buf, M_PACKET_HANDSHAKE);
    pkgsize += serialize_varint(buf, si->si_conninfo.proto);
    pkgsize += serialize_str(buf, si->si_conninfo.addr, strlen(si->si_conninfo.addr));
    pkgsize += serialize_short(buf, si->si_conninfo.port);
    pkgsize += serialize_varint(buf, si->si_conninfo.state);
    return pkgsize;
}

size_t build_slp(struct buffer *buf, void *data) {
    size_t pktsize = 0;
    pktsize += serialize_varint(buf, M_PACKET_SLPREQ);
    return pktsize;
}

size_t build_ping(struct buffer *buf, void *data) {
    size_t pktsize = 0;
    pktsize += serialize_varint(buf, M_PACKET_PING);
    pktsize += serialize_varint(buf, *(long *)data);
    return pktsize;
}

size_t build_login(struct buffer *buf, void *data) {
    struct userinfo *ui = (struct userinfo *)data;
    size_t pkgsize = 0;
    pkgsize += serialize_varint(buf, M_PACKET_LOGIN);
    pkgsize += serialize_str(buf, ui->ui_name, strlen(ui->ui_name));
    return pkgsize;
}

size_t build_encryption(struct buffer *buf, void *data) {
    struct serverinfo *si = (struct serverinfo *)data;
    struct buffer *share_secret = si->si_encinfo->e_secret;
    struct buffer *verify_token = si->si_encinfo->e_verify;

    share_secret->b_next = share_secret->b_data;
    verify_token->b_next = verify_token->b_data;

    int ret;
    // TODO: error handle
    ret = gen_rand_byte(share_secret, 16);

    RSA *rsa = DER_load_pubkey_from_str(si->si_encinfo->e_pubkey);
    int keysize = RSA_size(rsa);
    struct buffer *crypted_share_secret = new_buffer(keysize);
    struct buffer *crypted_verify_token = new_buffer(keysize);
    if (!crypted_share_secret || !crypted_verify_token) {
        // TODO: error handle
    }

    // TODO: error handle
    ret = RSA_encrypt_with_pubkey(rsa, share_secret, crypted_share_secret);
    ret = RSA_encrypt_with_pubkey(rsa, verify_token, crypted_verify_token);
    RSA_free(rsa);

    size_t pktsize = 0;
    pktsize += serialize_varint(buf, M_PACKET_ENCRYPTRES);
    pktsize += serialize_str(buf, crypted_share_secret->b_data, crypted_share_secret->b_size);
    pktsize += serialize_str(buf, crypted_verify_token->b_data, crypted_verify_token->b_size);
    del_buffer(crypted_share_secret);
    del_buffer(crypted_verify_token);
    return pktsize;
}

size_t build_chat(struct buffer *buf, void *data) {
    const char *str = (const char *)data;
    size_t pktsize = 0;
    pktsize += serialize_varint(buf, M_PACKET_CHAT);
    pktsize += serialize_str(buf, str, strlen(str));
    return pktsize;
}

size_t build_set_difficult(struct buffer *buf, void *data) {
    size_t pktsize = 0;
    pktsize += serialize_varint(buf, M_PACKET_SET_DIFFICULT);
    pktsize += serialize_varint(buf, *(int32_t *)data);
    return pktsize;
}
