#ifndef __COMPRESS_H
#define __COMPRESS_H
#define Z_CHUNK 12
#include "utils.h"

int mc_deflat_pkt(struct bytearray *arr_in, struct bytearray *arr_out);
int mc_inflat_pkt(struct bytearray *arr_in, struct bytearray *arr_out);

#endif // __COMPRESS_H