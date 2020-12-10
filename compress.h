#ifndef __COMPRESS_H
#define __COMPRESS_H

#define Z_CHUNK 512
#include "utils.h"

int mc_deflat_pkt(struct buffer *arr_in, struct buffer *arr_out);
int mc_inflat_pkt(struct buffer *arr_in, struct buffer *arr_out);

#endif // __COMPRESS_H