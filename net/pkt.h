#ifndef __MC_PKT_H
#define __MC_PKT_H
#include "type.h"
#include <sys/types.h>

int to_varint(int val, varint *out);
int to_varlong(long val, varlong *out);

void *serialize_varint(void *buf, const char *val);
void *serialize_short(void *buf, const short val);
void *serialize_str(void *buf, const char *val);

ssize_t deserialize_verint(byte const *buf, int *out);
ssize_t deserialize_str(byte const *buf, char *dst, size_t n);

#endif // __MC_PKT_H
