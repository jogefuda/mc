#include "pkt.h"
#include "../crypto.h"
#include "../utils.h"
#include "../compress.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

// debug
#include <fcntl.h>

// deserialize
static ssize_t fread_varint(int fd, int32_t *out)
{
    uint8_t tmp;
    size_t nbytes = 0;
    ssize_t n;
    *out = 0;

    do
    {
        if ((n = read(fd, &tmp, 1)) < 1)
            return n;
        *out |= (tmp & 0b1111111) << (7 * nbytes++);
    } while (tmp & 0b10000000);

    return nbytes;
}

static size_t deserialize_varint(struct buffer *buf, int32_t *out)
{
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

static size_t deserialize_str(struct buffer *buf, struct buffer *out)
{
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

// serialize
static size_t serialize_varint(struct buffer *buf, int32_t val)
{
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

static size_t serialize_short(struct buffer *buf, short val)
{
    inc_buffer_if_not_enough(buf, 2);
    char *_buf = buf->b_next;
    _buf[0] = (val >> 8) & 0xff;
    _buf[1] = val & 0xff;
    buf->b_next += 2;
    buf->b_size += 2;
    return sizeof(short);
}

static size_t serialize_str(struct buffer *buf, const char *str, size_t n)
{
    inc_buffer_if_not_enough(buf, 5 + n);
    char *_buf = buf->b_next;
    size_t vl = serialize_varint(buf, n);
    memcpy(buf->b_next, str, n);
    buf->b_next += n;
    buf->b_size += n;
    return vl + n;
}

// parse packet
void parse_setcompress(struct serverinfo *si, struct buffer *buf) {
    int32_t thresh;
    deserialize_varint(buf, &thresh);
    si->si_conninfo.thresh = thresh;
}

//
ssize_t read_packet(struct serverinfo *si, struct userinfo *ui, void *userdata)
{
    int fd = si->si_conninfo.sockfd;
    int is_compressed = si->si_conninfo.thresh > 0;
    int state = si->si_conninfo.state;
    int ret;
    struct buffer *buf, *out;
    int32_t pktlen, uncompressed_pktlen, pkttype;
    size_t nbytes, remain_pktbytes;

    fread_varint(fd, &pktlen);
    buf = new_buffer(pktlen);
    if (buf == NULL) {
        // TODO: error handle
    }

    nbytes = 0;
    if (is_compressed)
        nbytes += fread_varint(fd, &uncompressed_pktlen);
    
    remain_pktbytes = (is_compressed)? pktlen - nbytes: pktlen;

    if ((ret = read(fd, buf->b_next, remain_pktbytes)) < 1) {
        // TODO: error handle
    }
    buf->b_size += ret;

    if (is_compressed) {
        // TODO: error handle
        out = new_buffer(buf->b_size);
        ret = mc_inflat_pkt(buf, out);
        del_buffer(buf);
        buf = out;
        out = NULL;
    }

    deserialize_varint(buf, &pkttype);

    if (state == 2) {
        switch (pkttype) {
            case M_PACKET_ENCRYPT:
                break;
            case M_PACKET_SETCOMPRESS:;
                parse_setcompress(si, buf);
                break;
            default:
                break;
                // consume broken packet
        }
    }
    // buf->b_next = buf->b_data;
    nbytes += deserialize_varint(buf, &pkttype);
    dump(buf->b_data, buf->b_size);
    printf("pkgsize: %d, %d\n", pktlen, pkttype);
    return 0;
}

ssize_t send_packet(enum MC_REQ type, struct serverinfo *si, struct userinfo *ui, void *data) {
    struct buffer *buf, *zbuf, *header;
    header = new_buffer(10);
    buf = new_buffer(128);
    int compress_enabled = si->si_conninfo.thresh > 0;
    int fd = si->si_conninfo.sockfd;
    int state = si->si_conninfo.state;

    size_t pktsize;
    switch (type)
    {
        case MC_REQ_HANDSHAKE:
            pktsize = build_handshake(buf, si); break;
        case MC_REQ_PING:
            pktsize = build_ping(buf, data); break;
        case MC_REQ_SPL:
            pktsize = build_slp(buf, NULL); break;
        case MC_REQ_LOGIN:
            pktsize = build_login(buf, ui); break;
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

    printf("--------  dump begin --------\n");
    dump(header->b_data, header->b_size);
    dump(buf->b_data, buf->b_size);
    write(fd, header->b_data, header->b_size);
    write(fd, buf->b_data, buf->b_size);
    printf("--------  dump end --------\n");

    del_buffer(header);
    del_buffer(buf);
    return 1;
}

size_t build_handshake(struct buffer *buf, void *data)
{
    struct serverinfo *si = (struct serverinfo *)data;
    size_t pkgsize = 0;
    pkgsize += serialize_varint(buf, M_PACKET_HANDSHAKE);
    pkgsize += serialize_varint(buf, si->si_conninfo.proto);
    pkgsize += serialize_str(buf, si->si_conninfo.addr, strlen(si->si_conninfo.addr));
    pkgsize += serialize_short(buf, si->si_conninfo.port);
    pkgsize += serialize_varint(buf, si->si_conninfo.state);
    return pkgsize;
}

size_t build_slp(struct buffer *buf, void *data)
{
    size_t pktsize = 0;
    pktsize += serialize_varint(buf, M_PACKET_SERVER_LIST);
    return pktsize;
}

size_t build_ping(struct buffer *buf, void *data)
{
    size_t pktsize = 0;
    pktsize += serialize_varint(buf, M_PACKET_PING);
    pktsize += serialize_varint(buf, *(long *)data);
    return pktsize;
}

size_t build_login(struct buffer *buf, void *data)
{
    struct userinfo *ui = (struct userinfo *)data;
    size_t pkgsize = 0;
    pkgsize += serialize_varint(buf, M_PACKET_LOGIN);
    pkgsize += serialize_str(buf, ui->ui_name, strlen(ui->ui_name));
    return pkgsize;
}

size_t build_encryption(struct buffer *buf, void *data)
{
    struct serverinfo *si = (struct serverinfo *)data;
    struct bytearray *share_secret = &si->si_encinfo.e_secret;
    struct bytearray *verify_token = &si->si_encinfo.e_verify;

    int ret;
    ret = gen_rand_byte(share_secret, 16);

    struct bytearray crypted_share_secret;
    struct bytearray crypted_verify_token;

    RSA *rsa = DER_load_pubkey_from_str(&si->si_encinfo.e_pubkey);
    RSA_encrypt_with_pubkey(rsa, share_secret, &crypted_share_secret);
    RSA_encrypt_with_pubkey(rsa, &verify_token, &crypted_verify_token);
    RSA_free(rsa);

    size_t pktsize = 0;
    pktsize += serialize_varint(buf, M_PACKET_ENCRYPT);
    pktsize += serialize_str(buf, crypted_share_secret.b_data, crypted_share_secret.b_size);
    pktsize += serialize_str(buf, crypted_verify_token.b_data, crypted_verify_token.b_size);
    return pktsize;
}

size_t build_chat (struct buffer *buf, void *data)
{
    const char *str = (const char *)data;
    size_t pktsize = 0;
    pktsize += serialize_varint(buf, M_PACKET_CHAT);
    pktsize += serialize_str(buf, str, strlen(str));
    return pktsize;
}

size_t build_set_difficult(struct buffer *buf, void *data)
{
    size_t pktsize = 0;
    pktsize += serialize_varint(buf, M_PACKET_SET_DIFFICULT);
    pktsize += serialize_varint(buf, *(int32_t *)data);
    return pktsize;
}
