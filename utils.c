#include "utils.h"
#include <stdlib.h>
#include <stdio.h>

void dump(void *buf, int n) {
  char *_buf = buf;
  int a = n;
  while (a-- > 0)
    printf("%x ", (*_buf++) & 0xff);

  putc('\n', stdout);

  a = n;
  _buf = buf;
  while (a-- > 0)
    printf("%c", (*_buf++));
  putc('\n', stdout);
}

void *create_bytearray(size_t len) {
  return malloc(len);
}

void destroy_bytearray(void *ptr) {
  free(ptr);
}

/*
long vitohl(const byte *const buf, size_t *len)
{
  long ret = 0;
  size_t nRead = 0;
  byte *_buf = (byte *)buf;

  do
  {
    ret += (*_buf & 0b01111111) << (7 * nRead++);
  } while ((*_buf++ & 0b10000000) > 0);

  if (len != NULL)
    *len = nRead;

  return ret;
}
*/
