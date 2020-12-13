
#ifndef __SERIALIZE_H
#define __SERIALIZE_H
#include "../utils.h"
#include <sys/types.h>
#include <openssl/evp.h>

ssize_t fread_varint(int fd, int32_t *out, EVP_CIPHER_CTX *ctx);

#define deserialize_byte(buf, out) deserialize_char(buf, out)
#define deserialize_bytearray(buf, out, len) deserialize_str(buf, out, len)
#define deserialize_float(buf, out) deserialize_int(buf, out)
#define deserialize_double(buf, out) deserialize_long(buf, out)
size_t deserialize_varint(struct buffer *buf, int32_t *out);
size_t deserialize_str(struct buffer *buf, struct buffer *out);
size_t deserialize_char(struct buffer *buf, int8_t *out);
size_t deserialize_short(struct buffer *buf, int16_t *out);
size_t deserialize_int(struct buffer *buf, int32_t *out);
size_t deserialize_long(struct buffer *buf, int64_t *out);

#define serialize_byte(buf, out) serialize_char(buf, out)
#define serialize_bytearray(buf, out, len) serialize_str(buf, out, len)
#define serialize_float(buf, out) serialize_int(buf, out)
#define serialize_double(buf, out) serialize_long(buf, out)
size_t serialize_varint(struct buffer *buf, int32_t val);
size_t serialize_str(struct buffer *buf, const char *str, size_t len);
size_t serialize_char(struct buffer *buf, int8_t val);
size_t serialize_short(struct buffer *buf, int16_t val);
size_t serialize_int(struct buffer *buf, int32_t val);
size_t serialize_long(struct buffer *buf, int64_t val);
#endif // __SERIALIZE_H
