#include "compress.h"
#include <zlib.h>
#include <assert.h>
#include <stdio.h>

int mc_deflat_pkt(struct buffer *in, struct buffer *out) {
    int ret, flush;
    size_t have, offset, need;
    char tmp_in[Z_CHUNK] = { 0 }, tmp_out[Z_CHUNK] = { 0 };
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        return ret;
    }

    do {
        strm.avail_in = in->b_size - strm.total_in;
        strm.next_in = in->b_data + strm.total_in;
        flush = (in->b_size > strm.total_in) ? Z_NO_FLUSH : Z_FINISH;
        do {
            offset = strm.total_out;
            strm.avail_out = Z_CHUNK;
            strm.next_out = tmp_out;
            ret = deflate(&strm, flush);
            have = Z_CHUNK - strm.avail_out;

            if (!inc_buffer_if_not_enough(out, (have + (strm.total_out - out->b_allocsize)) * 1.3)) {
                deflateEnd(&strm);
                return Z_MEM_ERROR;
            }

            memcpy(out->b_data + offset, tmp_out, have);
            out->b_size += have;
        } while (strm.avail_out == 0);
        // assert(strm.avail_in == 0);
    } while (flush != Z_FINISH);

    deflateEnd(&strm);
    return Z_OK;
}

int mc_inflat_pkt(struct buffer *in, struct buffer *out) {
    int ret, flush;
    size_t have, offset, need;
    char tmp_in[Z_CHUNK] = { 0 }, tmp_out[Z_CHUNK] = { 0 };
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
        strm.avail_in = in->b_size - strm.total_in;
        strm.next_in = in->b_data + strm.total_in;
        flush = (in->b_size > strm.total_in) ? Z_NO_FLUSH : Z_FINISH;
        do {
            offset = strm.total_out;
            strm.avail_out = Z_CHUNK;
            strm.next_out = tmp_out;
            ret = inflate(&strm, flush);
            have = Z_CHUNK - strm.avail_out;

            if (!inc_buffer_if_not_enough(out, (have + (strm.total_out - out->b_allocsize)) * 1.3)) {
                inflateEnd(&strm);
                return Z_MEM_ERROR;
            }

            memcpy(out->b_data + offset, tmp_out, have);
            out->b_size += have;
        } while (strm.avail_out == 0);
        // assert(strm.avail_in == 0);
    } while (flush != Z_FINISH);

    inflateEnd(&strm);
    return Z_OK;
}