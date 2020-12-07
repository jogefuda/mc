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

int bytearray_increase(struct bytearray *arr, size_t size) {
  void *newptr = realloc(arr->b_data, arr->b_allocsize + size);
  if (newptr == NULL) return NULL;
  arr->b_data = newptr;
  arr->b_allocsize = arr->b_allocsize + size;
  return newptr;
}

struct bytearray *bytearray_create(size_t len) {
  struct bytearray *arr = malloc(sizeof(struct bytearray));
  arr->b_data = malloc(len);
  arr->b_size = 0;
  arr->b_allocsize = len;
  return arr;
}

void bytearray_destroy(struct bytearray *ptr) {
  if (!ptr) return;
  if (ptr->b_data) free(ptr->b_data);
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
