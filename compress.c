#include "compress.h"
#include <zlib.h>
#include <assert.h>
#include <stdio.h>

int mc_deflat_pkt(struct bytearray *arr_in, struct bytearray *arr_out)
{
    int ret, flush;
    size_t have, offset, need;
    char in[Z_CHUNK], out[Z_CHUNK];
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK)
    {
        deflateEnd(&strm);
        return ret;
    }

    do
    {
        need = arr_in->b_size - strm.total_in;
        strm.avail_in = (need >= Z_CHUNK)? Z_CHUNK: need;
        strm.next_in = arr_in->b_data + strm.total_in;
        flush = (arr_in->b_size > strm.total_in)? Z_NO_FLUSH: Z_FINISH;
        do
        {
            offset = strm.total_out;
            strm.avail_out = Z_CHUNK;
            strm.next_out = out;
            ret = deflate(&strm, flush);
            have = Z_CHUNK - strm.avail_out;
            
            if (arr_out->b_allocsize < strm.total_out
                && inc_bytearray(arr_out, (have + (strm.total_out - arr_out->b_allocsize)) * 1.3) == NULL) {
                    deflateEnd(&strm);
                    return Z_MEM_ERROR;
                }

            memcpy(arr_out->b_data + offset, out, have);
            arr_out->b_size += have;
        } while (strm.avail_out == 0);
        // assert(strm.avail_in == 0);
    } while (flush != Z_FINISH);

    deflateEnd(&strm);
    return Z_OK;
}

int mc_inflat_pkt(struct bytearray *arr_in, struct bytearray *arr_out) {
    int ret, flush;
    size_t need, have;
    char in[Z_CHUNK], out[Z_CHUNK];
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    ret = inflateInit(&strm);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        return ret;
    }

    do {
        need = arr_in->b_size - strm.total_in;
        strm.avail_in = (need >= Z_CHUNK)? Z_CHUNK: need;
        strm.next_in  = arr_in->b_data + strm.total_in;
        flush = (arr_in->b_size > strm.total_in)? Z_NO_FLUSH: Z_FINISH;

        do {
            strm.avail_out = Z_CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, flush);
            have = Z_CHUNK - strm.avail_out;

            if (arr_out->b_allocsize < strm.total_out
                && inc_bytearray(arr_out, (have + (strm.total_out - arr_out->b_allocsize)) * 1.3) == NULL) {
                    inflateEnd(&strm);
                    return Z_MEM_ERROR;
                }

            memcpy(arr_out->b_data, out, have);
        } while (strm.avail_out == 0);
    } while (flush != Z_FINISH);

    inflateEnd(&strm);
    return ret;
}