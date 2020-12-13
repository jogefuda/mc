#include "hash.h"
#include <openssl/sha.h>
#include <gmp.h>

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

int mc_hash_final(EVP_MD_CTX *ctx, char *out_buf, unsigned int *len) {
    unsigned char tmp[SHA_DIGEST_LENGTH];
    unsigned char str_tmp[SHA_DIGEST_LENGTH * 2 + 1];
    unsigned int tmp_len;
    if (!EVP_DigestFinal(ctx, tmp, &tmp_len))
        return 0;

    for (size_t i = 0; i < SHA_DIGEST_LENGTH; i++)
        sprintf(str_tmp + i * 2, "%02x", *(tmp + i) & 0xff);

    mpz_t bn, rbn;
    mpz_init(bn);
    int a = mpz_set_str(bn, str_tmp, 16);
    if (mpz_tstbit(bn, 159)) {
        for (size_t i = 0; i < 20 * 8; i++) {
            if (mpz_tstbit(bn, i))
                mpz_clrbit(bn, i);
            else
                mpz_setbit(bn, i);
        }

        mpz_init(rbn);
        mpz_add_ui(rbn, bn, 1);
        mpz_get_str(out_buf + 1, 16, rbn);
        mpz_clear(rbn);
        out_buf[0] = '-';
    } else {
        mpz_get_str(out_buf, 16, bn);
        mpz_clear(bn);
    }

    mc_hash_init(ctx);
    return 1;
}

void mc_hash_clean(EVP_MD_CTX *ctx) {
    // EVP_MD_CTX_cleanup(ctx);
    EVP_MD_CTX_destroy(ctx);
}
