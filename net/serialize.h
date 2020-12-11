
#ifndef __SERIALIZE_H
#define __SERIALIZE_H
#include "../utils.h"
#include <sys/types.h>
#include <openssl/evp.h>
ssize_t fread_varint(int fd, int32_t *out, EVP_CIPHER_CTX *ctx);

size_t deserialize_varint(struct buffer *buf, int32_t *out);
size_t deserialize_str(struct buffer *buf, struct buffer *out);
size_t deserialize_short(struct buffer *buf, int16_t *out);
size_t deserialize_long(struct buffer *buf, int64_t *out);
size_t deserialize_char(struct buffer *buf, int8_t *out);

size_t serialize_varint(struct buffer *buf, int32_t val);
size_t serialize_short(struct buffer *buf, short val);
size_t serialize_str(struct buffer *buf, const char *str, size_t n);
size_t serialize_long(struct buffer *buf, long val);
#endif // __SERIALIZE_H