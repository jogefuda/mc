#include "pkt.h"
#include "pktparser.h"
#include "auth.h" // may delete after impl queue
#include "serialize.h"
#include "../crypto.h"
#include "../compress.h"
#include "../utils.h"
#include "../log.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

/* Read/Decrypt/Decompress the packet and send to parser */
ssize_t read_packet(struct serverinfo *si, struct userinfo *ui, void *userdata) {
    int fd = si->si_conninfo.sockfd;
    int compress_enabled = si->si_conninfo.thresh > 0;
    int encrypt_enabled = si->si_encinfo->e_decctx != NULL;
    EVP_CIPHER_CTX *cipher = si->si_encinfo->e_decctx;
    int state = si->si_conninfo.state;
    int ret;
    struct buffer *buf, *zbuf;
    int32_t pktlen, uncompressed_pktlen, pkttype;
    size_t nbytes, remain_pktbytes;

    fread_varint(fd, &pktlen, cipher);
    buf = new_buffer(pktlen);
    if (buf == NULL)
        return -1;

    nbytes = 0;
    if (compress_enabled)
        nbytes += fread_varint(fd, &uncompressed_pktlen, cipher);

    remain_pktbytes = (compress_enabled) ? pktlen - nbytes : pktlen;

    // TODO: use loop for read
    if ((ret = read(fd, buf->b_data, remain_pktbytes)) < 1) {
        log_fatal(mc_err_getstr(M_ERR_DATA));
        return -1;
    }

    buf->b_size = ret;

    /* Decrypt packet */
    if (encrypt_enabled)
        aes_cipher_update(cipher, buf, buf);

    /* Decompress packet */
    if (compress_enabled && uncompressed_pktlen > 0) {
        zbuf = new_buffer(uncompressed_pktlen);
        if (zbuf == NULL) {
            del_buffer(buf);
            return -1;
        }

        buf->b_next = buf->b_data;
        ret = mc_inflat_pkt(buf, zbuf);
        if (ret != M_SUCCESS) {
            del_buffer(buf);
            del_buffer(zbuf);
            return -1;
        }

        del_buffer(buf);
        buf = zbuf;
        zbuf = NULL;
    }

    /* Get packet type */
    deserialize_varint(buf, &pkttype);
    // TODO: 1. impl state 1 and 2
    //       2. is proccessed variable
    if (state == M_STATE_PLAY) {
        switch (pkttype) {
            case M_PACKET_KEEPALIVE_C:
                parse_keepalive(si, buf);
                break;
            case M_PACKET_SET_DIFFICULT_C:
                parse_set_difficult(si, buf);
                break;
            case M_PACKET_DECLARE_COMMAND:
                parse_declare_command(si, buf);
                break;
            case M_PACKET_PLAYER_STATUS:
                parse_player_status(si, buf);
                break;
            case M_PACKET_PLAYER_POSITION_AND_LOOK:
                parse_player_position_and_look(si, buf);
                break;
            case M_PACKET_UPDATE_VIEW_POSITION:
                parse_update_view_position(si, buf);
                break;
        }
    } else if (state == M_STATE_LOGIN) {
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

        }
    } else if (state == M_STATE_HANDSHAKE) {
        // M_PACKET_SLPREQ
        // M_PACKET_PING
    }

    // TODO:
    // check if packet is borken
    // consume broken packet (if any)

    del_buffer(buf);
    return 0;
}

/* Send/Encrypt/Compress the packet */
ssize_t send_packet(enum M_REQ type, struct serverinfo *si, struct userinfo *ui, void *data) {
    int ret;
    char *pdata;
    struct buffer *buf, *zbuf;

    buf = new_buffer(128);

    if (buf == NULL)
        return -1;

    /* reserve for header size */
    buf->b_next = buf->b_data + 10;
    buf->b_allocsize -= 10;

    int compress_enabled = si->si_conninfo.thresh > 0;
    int encrypt_enabled = si->si_encinfo->e_encctx != 0;
    int fd = si->si_conninfo.sockfd;
    int state = si->si_conninfo.state;

    size_t pktsize;
    switch (type) {
        case M_REQ_HANDSHAKE:
            pktsize = build_handshake(buf, si); break;
        case M_REQ_PING:
            pktsize = build_ping(buf, data); break;
        case M_REQ_SPL:
            pktsize = build_slp(buf, NULL); break;
        case M_REQ_LOGIN:
            pktsize = build_login(buf, ui); break;
        case M_REQ_ENCRYPTRES:
            pktsize = build_encryption(buf, si);

            // TODO: queue.
            mc_auth(si, NULL);
            mc_init_cipher(si);
            break;
        case M_REQ_CHAT:
            pktsize = build_chat(buf, data); break;
        case M_REQ_SET_DIFFICULT:
            pktsize = build_set_difficult(buf, data); break;
        case M_REQ_KEEPALIVE:
            pktsize = build_keepalive(buf, data); break;
    }

    if (compress_enabled) {
        if (buf->b_size > si->si_conninfo.thresh) {
            zbuf = new_buffer(buf->b_allocsize * 0.8);
            if (zbuf == NULL) {
                del_buffer(buf);
                return -1;
            }

            /* reseve 10 bytes for header */
            buf->b_next = buf->b_data + 10;
            zbuf->b_next += 10;
            mc_deflat_pkt(buf, zbuf);
            del_buffer(buf);
            buf = zbuf;

            buf->b_next = pdata = buf->b_data + 10
                - get_varint_len(buf->b_size + get_varint_len(pktsize))
                - get_varint_len(pktsize);
            serialize_varint(buf, buf->b_size + get_varint_len(pktsize));
            serialize_varint(buf, pktsize);
        } else {
            buf->b_next = pdata = buf->b_data + 10
                - get_varint_len(pktsize + get_varint_len(0))
                - get_varint_len(0);
            serialize_varint(buf, pktsize + get_varint_len(0));
            serialize_varint(buf, 0);
        }
    } else {
        buf->b_next = pdata = buf->b_data + 10
            - get_varint_len(pktsize);
        serialize_varint(buf, pktsize);
    }

    if (encrypt_enabled) {
        buf->b_next = pdata;
        aes_cipher_update(si->si_encinfo->e_encctx, buf, buf);
    }

    ssize_t wbytes, total_wbytes;
    wbytes = 0;
    total_wbytes = 0;
    do {
        wbytes = write(fd, pdata, buf->b_size);
        if (wbytes == -1)
            return -1;
        buf->b_size -= wbytes;
        total_wbytes += wbytes;
    } while (buf->b_size);

    del_buffer(buf);
    return total_wbytes;
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
    pktsize += serialize_varint(buf, M_PACKET_SET_DIFFICULT_S);
    pktsize += serialize_varint(buf, *(int32_t *)data);
    return pktsize;
}

size_t build_keepalive(struct buffer *buf, void *data) {
    size_t pktsize = 0;
    pktsize += serialize_varint(buf, M_PACKET_KEEPALIVE_S);
    pktsize += serialize_long(buf, *(int64_t *)data);
    return pktsize;
}
