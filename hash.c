#include "hash.h"
#include "minecraft.h"
#include "log.h"
#include "utils.h"
#include <openssl/sha.h>
#include <gmp.h>

/* Initialize Digest Context if not initialize yet */
EVP_MD_CTX *mc_hash_init(EVP_MD_CTX *ctx) {
    // NOTE: I dont know if ctx will create fail or not ?
    if (ctx == NULL) {
        ctx = EVP_MD_CTX_create();
        EVP_MD_CTX_init(ctx);
    }

    const EVP_MD *md = EVP_get_digestbyname("SHA1");
    EVP_DigestInit_ex(ctx, md, NULL);
    return ctx;
}

/* Update Digest */
int mc_hash_update(EVP_MD_CTX *ctx, const char *data, size_t len) {
    int ret;

    if ((ret = EVP_DigestUpdate(ctx, data, len)) == 0) {
        log_fatal(mc_err_getstr(M_ERR_DIGEST));
        return M_FAIL;
    }
    return M_SUCCESS;
}

/* Finalize the Digest and get result to out */
int mc_hash_final(EVP_MD_CTX *ctx, char *out) {
    unsigned char tmp[SHA_DIGEST_LENGTH];
    unsigned char str_tmp[M_DIGEST_LENGTH];
    unsigned int tmp_len;
    if (!EVP_DigestFinal(ctx, tmp, &tmp_len)) {
        log_fatal(mc_err_getstr(M_ERR_DIGEST));
        return M_FAIL;
    }

    /* Convert Digest to string form */
    for (size_t i = 0; i < SHA_DIGEST_LENGTH; i++)
        sprintf(str_tmp + i * 2, "%02x", *(tmp + i) & 0xff);

    mpz_t bn, rbn;
    mpz_init(bn);
    int a = mpz_set_str(bn, str_tmp, 16);
    if (mpz_tstbit(bn, 159)) { /* if is negative */
        /* Two's complement then add 1 */
        for (size_t i = 0; i < 20 * 8; i++) {
            if (mpz_tstbit(bn, i))
                mpz_clrbit(bn, i);
            else
                mpz_setbit(bn, i);
        }

        mpz_init(rbn);
        mpz_add_ui(rbn, bn, 1);
        mpz_get_str(out + 1, 16, rbn);
        mpz_clear(rbn);
        out[0] = '-';
    } else { /* if is positive */
        mpz_get_str(out, 16, bn);
        mpz_clear(bn);
    }

    /* Renew the Digest context */
    mc_hash_init(ctx);
    return M_SUCCESS;
}

/* Release Digest Context */
void mc_hash_clean(EVP_MD_CTX *ctx) {
    // EVP_MD_CTX_cleanup(ctx);
    if (ctx)
        EVP_MD_CTX_destroy(ctx);
}
