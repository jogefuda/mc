#include "serialize.h"
#include "../crypto.h"
#include <unistd.h>
#include <string.h>

// deserialize
ssize_t fread_varint(int fd, int32_t *out, EVP_CIPHER_CTX *ctx) {
    uint8_t tmp;
    size_t nbytes = 0;
    ssize_t n;
    *out = 0;

    do {
        if ((n = read(fd, &tmp, 1)) < 1)
            return n;

        if (ctx)
            aes_cipher_update_u8(ctx, tmp, &tmp);

        *out |= (tmp & 0b1111111) << (7 * nbytes++);
    } while (tmp & 0b10000000);

    return nbytes;
}

size_t deserialize_varint(struct buffer *buf, int32_t *out) {
    uint8_t tmp;
    size_t nbytes = 0;
    ssize_t n;
    *out = 0;
    char *_buf = buf->b_next;

    do {
        tmp = *_buf++;
        *out |= (tmp & 0b1111111) << (7 * nbytes++);
    } while (tmp & 0b10000000);

    buf->b_next = _buf;
    return nbytes;
}

size_t deserialize_str(struct buffer *buf, struct buffer *out) {
    int32_t len;
    deserialize_varint(buf, &len);

    if (len == 0)
        return 0;

    inc_buffer_if_not_enough(out, len + 1);
    memcpy(out->b_next, buf->b_next, len);

    buf->b_next += len;
    out->b_next += len + 1;
    out->b_size += len;
    return len;
}

size_t deserialize_char(struct buffer *buf, int8_t *out) {
    *out = *buf->b_next++;
    return 1;
}

size_t deserialize_short(struct buffer *buf, int16_t *out) {
    char *_out = (char *)out;
    _out[1] = *buf->b_next++;
    _out[0] = *buf->b_next++;
    return 2;
}

size_t deserialize_int(struct buffer *buf, int32_t *out) {
    char *_out = (char *)out;
    _out[3] = *buf->b_next++;
    _out[2] = *buf->b_next++;
    _out[1] = *buf->b_next++;
    _out[0] = *buf->b_next++;
    return 4;
}

size_t deserialize_long(struct buffer *buf, int64_t *out) {
    char *_out = (char *)out;
    _out[7] = *buf->b_next++;
    _out[6] = *buf->b_next++;
    _out[5] = *buf->b_next++;
    _out[4] = *buf->b_next++;
    _out[3] = *buf->b_next++;
    _out[2] = *buf->b_next++;
    _out[1] = *buf->b_next++;
    _out[0] = *buf->b_next++;
    return 8;
}

// serialize
size_t serialize_varint(struct buffer *buf, int32_t val) {
    inc_buffer_if_not_enough(buf, 5);
    char *_buf = buf->b_next;
    char tmp;
    size_t n = 0;

    do {
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

size_t serialize_str(struct buffer *buf, const char *str, size_t len) {
    inc_buffer_if_not_enough(buf, 5 + len);
    char *_buf = buf->b_next;
    size_t vl = serialize_varint(buf, len);
    memcpy(buf->b_next, str, len);
    buf->b_next += len;
    buf->b_size += len;
    return vl + len;
}

size_t serialize_char(struct buffer *buf, int8_t val) {
    inc_buffer_if_not_enough(buf, 1);
    char *_buf = buf->b_next;
    _buf[0] = val;
    ++buf->b_next;
    ++buf->b_size;
    return 1;
}

size_t serialize_short(struct buffer *buf, int16_t val) {
    inc_buffer_if_not_enough(buf, 2);
    char *_buf = buf->b_next;
    _buf[0] = (val >> 8) & 0xff;
    _buf[1] = val & 0xff;
    buf->b_next += 2;
    buf->b_size += 2;
    return 2;
}

size_t serialize_int(struct buffer *buf, int32_t val) {
    inc_buffer_if_not_enough(buf, 4);
    *buf->b_next++ = (val >> (8 * 3)) & 0xff;
    *buf->b_next++ = (val >> (8 * 2)) & 0xff;
    *buf->b_next++ = (val >> (8 * 1)) & 0xff;
    *buf->b_next++ = (val >> (8 * 0)) & 0xff;
    buf->b_size += 8;
    return 8;
}

size_t serialize_long(struct buffer *buf, int64_t val) {
    inc_buffer_if_not_enough(buf, 8);
    *buf->b_next++ = (val >> (8 * 7)) & 0xff;
    *buf->b_next++ = (val >> (8 * 6)) & 0xff;
    *buf->b_next++ = (val >> (8 * 5)) & 0xff;
    *buf->b_next++ = (val >> (8 * 4)) & 0xff;
    *buf->b_next++ = (val >> (8 * 3)) & 0xff;
    *buf->b_next++ = (val >> (8 * 2)) & 0xff;
    *buf->b_next++ = (val >> (8 * 1)) & 0xff;
    *buf->b_next++ = (val >> (8 * 0)) & 0xff;
    buf->b_size += 8;
    return 8;
}
