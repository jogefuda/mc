#include "utils.h"
#include "minecraft.h"
#include "log.h"
#include <stdlib.h>
#include <stdio.h>

void *inc_buffer(struct buffer *arr, size_t size) {
    /* realloc buf size to (allocated + size) */
    size_t newsize = arr->b_allocsize + size;
    void *newptr = realloc(arr->b_data, newsize);
    if (newptr == NULL)
        return NULL;

    arr->b_next = newptr + (arr->b_next - arr->b_data);
    arr->b_data = newptr;
    arr->b_allocsize = newsize;
    return newptr;
}

int inc_buffer_if_not_enough(struct buffer *arr, size_t size) {
    /* check buffer is already sufficient */
    if (arr->b_allocsize >= (arr->b_size + size))
        return M_SUCCESS;

    /* check buffer is success to realloc */
    if (inc_buffer(arr, size))
        return M_SUCCESS;

    log_fatal(mc_err_getstr(M_ERR_MEMORY));
    return M_FAIL;
}

struct buffer *new_buffer(size_t len) {
    /* allocate buffer structure and its data container */
    struct buffer *arr = malloc(sizeof(struct buffer));
    if (arr == NULL)
        return NULL;

    arr->b_data = malloc(len);
    if (arr->b_data == NULL) {
        free(arr);
        return NULL;
    }

    /* Init the buffer */
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
