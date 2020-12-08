#ifndef __UTILS_H
#define __UTILS_H

#include <sys/types.h>

typedef struct bytearray {
    size_t b_size;
    size_t b_allocsize;
    char *b_data;
} bytearray_t;

typedef struct buffer {
    size_t b_size;
    size_t b_allocsize;
    char *b_data;
    char *b_next;
} buffer_t;

void *inc_bytearray(struct bytearray *arr, size_t size);
struct bytearray *new_bytearray(size_t len);
void del_bytearray(struct bytearray *ptr);

int inc_buffer_if_not_enough(struct buffer *arr, size_t size);
void *inc_buffer(struct buffer *arr, size_t size);
struct buffer *new_buffer(size_t len);
void del_buffer(struct buffer *ptr);

int get_varint_len(int32_t val);

void dump(void *buf, int n);
/*
#define vitoh(__v, __n) ((int)vitohl(__v, __n))
#define vitohs(__v, __n) ((short)vitohl(__v, __n))

*/
#endif // __UTILS_H
