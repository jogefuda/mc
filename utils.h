#ifndef __UTILS_H
#define __UTILS_H

#include <sys/types.h>

typedef struct bytearray {
    char *b_data;
    size_t b_size;
    size_t b_allocsize;
} bytearray_t;

int bytearray_increase(struct bytearray *arr, size_t size);
struct bytearray *bytearray_create(size_t len);
void bytearray_destroy(struct bytearray *ptr);

void dump(void *buf, int n);
/*
#define vitoh(__v, __n) ((int)vitohl(__v, __n))
#define vitohs(__v, __n) ((short)vitohl(__v, __n))

*/
#endif // __UTILS_H
