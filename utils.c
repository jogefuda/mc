#include "utils.h"
#include "minecraft.h"
#include <stdlib.h>
#include <stdio.h>

void *inc_bytearray(struct bytearray *arr, size_t size) {
    void *newptr = realloc(arr->b_data, arr->b_allocsize + size);
    if (newptr == NULL)
        return NULL;
    arr->b_data = newptr;
    arr->b_allocsize = arr->b_allocsize + size;
    return newptr;
}

struct bytearray *new_bytearray(size_t len) {
    struct bytearray *arr = malloc(sizeof(struct bytearray));
    if (arr == NULL)
        return NULL;

    arr->b_data = malloc(len);
    if (arr->b_data == NULL) {
        free(arr);
        return NULL;
    }

    arr->b_size = 0;
    arr->b_allocsize = len;
    return arr;
}

void del_bytearray(struct bytearray *ptr) {
    if (ptr && ptr->b_data)
        free(ptr->b_data);
    if (ptr)
        free(ptr);
}

int inc_buffer_if_not_enough(struct buffer *arr, size_t size) {
    if (arr->b_allocsize >= (arr->b_size + size)) return 1;
    if (arr->b_allocsize < (arr->b_size + size) && inc_buffer(arr, size)) {
        return 1;
    }

    log_fatal(mc_err_getstr(M_ERR_MEMORY));
    return 0;
}

void *inc_buffer(struct buffer *arr, size_t size) {
    if (inc_bytearray(arr, size) != 0) {
        arr->b_next = arr->b_data + arr->b_size;
        return 1;
    }
    return 0;
}

struct buffer *new_buffer(size_t len) {
    struct buffer *arr = malloc(sizeof(struct buffer));
    if (arr == NULL)
        return NULL;

    arr->b_data = malloc(len);
    if (arr->b_data == NULL) {
        free(arr);
        return NULL;
    }

    arr->b_next = arr->b_data;
    arr->b_size = 0;
    arr->b_allocsize = len;
    return arr;
}

void del_buffer(struct buffer *ptr) {
    if (ptr && ptr->b_data)
        free(ptr->b_data);
    if (ptr)
        free(ptr);
}

int get_varint_len(int32_t val) {
    unsigned int _val = val;
    int n = 0;
    do {
        _val >>= 7;
        ++n;
    } while (_val > 0);
    return n;
}
