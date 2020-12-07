#include "hash.h"

EVP_MD_CTX *mc_hash_init(EVP_MD_CTX *ctx) {
    // TODO: ctx error handler
    if (ctx == NULL) {
        ctx = EVP_MD_CTX_create();
        EVP_MD_CTX_init(ctx);
    }

    // OpenSSL_add_all_digests();
    const EVP_MD *md = EVP_get_digestbyname("SHA1");
    EVP_DigestInit_ex(ctx, md, NULL);
    return ctx;
}

int mc_hash_update(EVP_MD_CTX *ctx, const char *data, size_t len) {
    return EVP_DigestUpdate(ctx, data, len);
}

int mc_hash_final(EVP_MD_CTX *ctx, char *buf, unsigned int *len) {
    unsigned char tmp[SHA_DIGEST_LENGTH];
    unsigned int tmp_len;
    if (!EVP_DigestFinal(ctx, tmp, &tmp_len)) return 0;

    if (tmp[0] & 0b10000000) {
        *buf++ = '-';
        for (size_t i = 0; i < tmp_len; i++)
            sprintf(buf+i, "%x", ~tmp[i]);
        // TODO: this may cause incorrect hash
        ++buf[tmp_len - 1];
    } else {
        memcpy(buf, tmp, tmp_len);
    }

    *len = tmp_len;
    mc_hash_init(ctx);
    return 1;
}

void mc_hash_clean(EVP_MD_CTX *ctx) {
    // EVP_MD_CTX_cleanup(ctx);
    EVP_MD_CTX_destroy(ctx);
}
