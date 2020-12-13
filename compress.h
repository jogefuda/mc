#ifndef __COMPRESS_H
#define __COMPRESS_H

#define Z_CHUNK 1024
#include "utils.h"

int mc_deflat_pkt(struct buffer *in, struct buffer *out);
int mc_inflat_pkt(struct buffer *in, struct buffer *out);

#endif // __COMPRESS_H
