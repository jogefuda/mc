#include "pkt.h"
#include "../crypto.h"
#include "../utils.h"
#include "../compress.h"
#include "auth.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

// debug
#include <fcntl.h>

// deserialize
static ssize_t fread_varint(int fd, int32_t *out, EVP_CIPHER_CTX *ctx) {
    uint8_t tmp;
    size_t nbytes = 0;
    ssize_t n;
    *out = 0;

    do
    {
        if ((n = read(fd, &tmp, 1)) < 1)
            return n;

        if (ctx)
            aes_cipher_update_u8(ctx, tmp, &tmp);

        *out |= (tmp & 0b1111111) << (7 * nbytes++);
    } while (tmp & 0b10000000);

    return nbytes;
}

static size_t deserialize_varint(struct buffer *buf, int32_t *out) {
    uint8_t tmp;
    size_t nbytes = 0;
    ssize_t n;
    *out = 0;
    char *_buf = buf->b_next;

    do
    {
        tmp = *_buf++;
        *out |= (tmp & 0b1111111) << (7 * nbytes++);
    } while (tmp & 0b10000000);

    buf->b_next = _buf;
    return nbytes;
}

static size_t deserialize_str(struct buffer *buf, struct buffer *out) {
    int32_t len;

    deserialize_varint(buf, &len);

    if (len == 0)
        return 0;

    inc_buffer_if_not_enough(out, len + 1);
    memcpy(out->b_next, buf->b_next, len);

    buf->b_next += len;
    out->b_next += len + 1;
    out->b_size += len;
    *(out->b_data + len + 1) = '\0';
    return len;
}

static size_t deserialize_short(struct buffer *buf, int16_t *out) {
    out[1] = buf->b_next++;
    out[0] = buf->b_next++;
    return 2;
}

static size_t deserialize_long(struct buffer *buf, int64_t *out) {
    out[7] = buf->b_next++;
    out[6] = buf->b_next++;
    out[5] = buf->b_next++;
    out[4] = buf->b_next++;
    out[3] = buf->b_next++;
    out[2] = buf->b_next++;
    out[1] = buf->b_next++;
    return 8;
}

// serialize
static size_t serialize_varint(struct buffer *buf, int32_t val) {
    inc_buffer_if_not_enough(buf, 5);
    char *_buf = buf->b_next;
    char tmp;
    size_t n = 0;

    do
    {
        tmp = val & 0b01111111;
        val >>= 7;
        if (val != 0)
            tmp |= 0b10000000;

        *_buf++ = tmp;
        ++n;
    } while (val != 0);

    buf->b_next = _buf;
    buf->b_size += n;
    return n;
}

static size_t serialize_short(struct buffer *buf, short val) {
    inc_buffer_if_not_enough(buf, 2);
    char *_buf = buf->b_next;
    _buf[0] = (val >> 8) & 0xff;
    _buf[1] = val & 0xff;
    buf->b_next += 2;
    buf->b_size += 2;
    return sizeof(short);
}

static size_t serialize_str(struct buffer *buf, const char *str, size_t n) {
    inc_buffer_if_not_enough(buf, 5 + n);
    char *_buf = buf->b_next;
    size_t vl = serialize_varint(buf, n);
    memcpy(buf->b_next, str, n);
    buf->b_next += n;
    buf->b_size += n;
    return vl + n;
}

// parse packet
void parse_setcompression(struct serverinfo *si, struct buffer *buf) {
    int32_t thresh;
    deserialize_varint(buf, &thresh);
    si->si_conninfo.thresh = thresh;
}

void parse_loginsuccess(struct serverinfo *si, struct buffer *buf) {
    si->si_conninfo.state = MC_STATUS_PLAY;
    // TODO: parse uuid string (16) 
}

void parse_keepalive(struct serverinfo *si, struct buffer *buf) {
    deserialize_long(buf, &si->si_conninfo.keepalive);
}

void parse_encryptreq(struct serverinfo *si, struct buffer *buf) {
    si->si_encinfo->e_id = new_buffer(10);
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

    nbytes = 0;
    if (compress_enabled)
        nbytes += fread_varint(fd, &uncompressed_pktlen, cipher);

    remain_pktbytes = (compress_enabled) ? pktlen - nbytes : pktlen;

    if ((ret = read(fd, buf->b_data, remain_pktbytes)) < 1) {
        // TODO: error handle
    }
    buf->b_size = ret;

    if (encrypt_enabled) {
        aes_cipher_update(cipher, buf, buf);
    }

    if (compress_enabled && uncompressed_pktlen > 0) {
        // TODO: error handle
        out = new_buffer(buf->b_size);
        ret = mc_inflat_pkt(buf, out);
        del_buffer(buf);
        buf = out;
        out = NULL;
    }

    deserialize_varint(buf, &pkttype);
    // TODO: 1. impl state 1 and 2
    //       2. is proccessed variable
    if (state == MC_STATUS_PLAY) {
        switch (pkttype) {
            case M_PACKET_KEEPALIVE:
                parse_keepalive(si, buf);
                break;
        }
    }
    else if (state == MC_STATUS_LOGIN) {
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
    nbytes += deserialize_varint(buf, &pkttype);
    dump(buf->b_data, buf->b_size);
    printf("pkgsize: %d, %d\n", pktlen, pkttype);

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
        }
        else {
            serialize_varint(header, pktsize + get_varint_len(0));
            serialize_varint(header, 0);
        }
    }
    else {
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
