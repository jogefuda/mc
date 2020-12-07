#include "compress.h"
#include <zlib.h>
#include <assert.h>
#include <stdio.h>
int mc_deflat_pkt(struct bytearray *arr_in, struct bytearray *arr_out)
{
    int ret, flush;
    size_t have, offset, need;
    z_stream strm;
    memset(&strm, 0, sizeof(z_stream));
    char in[Z_CHUNK], out[Z_CHUNK];
    ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK)
    {
        return ret;
    }

    need = arr_in->b_size - strm.total_in;
    do
    {
        strm.avail_in = (need > Z_CHUNK)? Z_CHUNK: need;
        strm.next_in = arr_in->b_data + have;
        flush = (need > Z_CHUNK)? Z_NO_FLUSH: Z_FINISH;
        do
        {
            offset = strm.total_out;
            strm.avail_out = Z_CHUNK;
            strm.next_out = out;
            ret = deflate(&strm, flush);
            have = Z_CHUNK - strm.avail_out;
            
            if (arr_out->b_allocsize < strm.total_out
                && bytearray_increase(arr_out, (have + (strm.total_out - arr_out->b_allocsize)) * 1.3) == NULL) {
                    goto err;
                }

            memcpy(arr_out->b_data + offset, out, have);
            arr_out->b_size += have;
        } while (strm.avail_out == 0 && 0);
        assert(strm.avail_in == 0);
    } while (flush != Z_FINISH);

    deflateEnd(&strm);
    return Z_OK;

err:;
    deflateEnd(&strm);
    return Z_MEM_ERROR;
}