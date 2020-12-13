#include "compress.h"
#include "minecraft.h"
#include "log.h"
#include <zlib.h>
#include <string.h>

/* zlib compress */
int mc_deflat_pkt(struct buffer *in, struct buffer *out) {
    int ret, flush;
    size_t have, offset, need;
    char tmp_out[Z_CHUNK];
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        log_fatal(mc_err_getstr(M_ERR_DEFLAT));
        return M_FAIL;
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
                return M_FAIL;
            }

            memcpy(out->b_data + offset, tmp_out, have);
        } while (strm.avail_out == 0);
    } while (flush != Z_FINISH);
    out->b_size = strm.total_out;

    deflateEnd(&strm);
    return M_SUCCESS;
}

/* zlib decompress */
int mc_inflat_pkt(struct buffer *in, struct buffer *out) {
    int ret, flush;
    size_t have, offset, need;
    char tmp_out[Z_CHUNK];
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    ret = inflateInit(&strm);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        log_fatal(mc_err_getstr(M_ERR_INFLAT));
        return M_FAIL;
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
                return M_FAIL;
            }

            memcpy(out->b_data + offset, tmp_out, have);
        } while (strm.avail_out == 0);
    } while (flush != Z_FINISH);
    out->b_size = strm.total_out;

    inflateEnd(&strm);
    return M_SUCCESS;
}
