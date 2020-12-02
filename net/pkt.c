#include "pkt.h"
#include <string.h>
#include <assert.h>

// utils
#define vitoh(__v, __n) ((int)vitohl(__v, __n))
#define vitohs(__v, __n) ((short)vitohl(__v, __n))
long vitohl(const byte *const buf, size_t *len) {
  long ret = 0;
  size_t nRead = 0;
  byte *_buf = (byte *)buf;

  do {
    ret += (*_buf & 0b01111111) << (7 * nRead++);
  } while ((*_buf++ & 0b10000000) > 0);

  if (len != NULL)
    *len = nRead;
  return ret;
}

int to_varint(int val, varint *out) {
  int nbytes = 0;
  char tmp = 0;
  char *_out = (char *)out;

  do {
    tmp = val & 0b01111111;
    val = (unsigned int)val >> 7;
    if (val != 0)
      tmp |= 0b10000000; // 0x80
    *(_out + nbytes++) = tmp;
    assert(nbytes <= 5);
  } while (val != 0);

  return nbytes;
}

int to_varlong(long val, varlong *out) {
  int nbytes = 0;
  char tmp = 0;
  char *_out = (char *)out;

  do {
    tmp = val & 0b01111111;
    val = (unsigned long)val >> 7;
    if (val != 0)
      tmp |= 0b10000000; // 0x80
    *(_out + nbytes++) = tmp;
    assert(nbytes <= 10);
  } while (val != 0);

  return nbytes;
}

// serialize
void *serialize_varint(void *buf, const char *val) {
  unsigned char tmp;
  char *_buf = buf;

  do {
    *_buf = *val++;
  } while ((*_buf++ & 0b10000000) > 0);

  return _buf;
}

void *serialize_short(void *buf, const short val) {
  char *_buf = buf;
  _buf[0] = val >> 8;
  _buf[1] = val >> 0;
  return buf + 2;
}

void *serialize_str(void *buf, const char *val) {
  char *_buf = buf;
  const char *_val = val;
  size_t len = strlen(val);

  varint vint;
  int n = to_varint(len, &vint);
  _buf = serialize_varint(_buf, vint);

  while (*_val) {
    *_buf++ = *_val++;
  }

  return _buf;
}

// deserialize
ssize_t deserialize_verint(byte const *buf, int *out) {
  size_t n = 0;
  *out = vitoh(buf, &n);
  return n;
}

ssize_t deserialize_str(byte const *buf, char *dst, size_t n) {
  return 0;
}
