#include "crypto.h"
#include "log.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <gnutls/gnutls.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

static char *PEM_START = "-----BEGIN PUBLIC KEY-----";
static char *PEM_END = "-----END PUBLIC KEY-----";

/* Load public key from PEM format */
static RSA* PEM_load_pubkey_from_str(const char* publicKeyStr) {
    // A BIO is an I/O abstraction (Byte I/O?)

    // BIO_new_mem_buf: Create a read-only bio buf with data
    // in string passed. -1 means string is null terminated,
    // so BIO_new_mem_buf can find the dataLen itself.
    // Since BIO_new_mem_buf will be READ ONLY, it's fine that publicKeyStr is const.
    BIO* bio = BIO_new_mem_buf((void*)publicKeyStr, -1); // -1: assume string is null terminated

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // NO NL

    // Load the RSA key from the BIO
    RSA* rsaPubKey = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if (rsaPubKey == NULL)
        log_fatal(mc_err_getstr(M_ERR_PUBKEY), ERR_error_string(ERR_get_error(), NULL));

    BIO_free(bio);
    return rsaPubKey;
}

/* Load public key from DER format */
RSA *DER_load_pubkey_from_str(struct buffer *arr) {
    /* Convert DER to PEM format */
    gnutls_datum_t raw, b64;
    raw.data = arr->b_data;
    raw.size = arr->b_size;
    gnutls_base64_encode2(&raw, &b64);
    char *outkey = malloc(strlen(PEM_START) + b64.size + strlen(PEM_END) + 1);
    sprintf(outkey, "%s\n%s\n%s", PEM_START, b64.data, PEM_END);

    /* Load public key from PEM format */
    RSA *rsa = PEM_load_pubkey_from_str(outkey);

    /* Clean up */
    gnutls_free(b64.data);
    free(outkey);
    return rsa;
}

/* Encrypt data from in to out with pubkey */
int RSA_encrypt_with_pubkey(RSA *rsa, struct buffer *in, struct buffer *out) {
    int ret;
    size_t keysize = RSA_size(rsa);
    if (M_FAIL == inc_buffer_if_not_enough(out, keysize))
        return -1;

    ret = RSA_public_encrypt(in->b_size, (unsigned char *)in->b_data, (unsigned char *)out->b_next, rsa, RSA_PKCS1_PADDING);

    if (ret == -1) {
        log_fatal(mc_err_getstr(M_ERR_ENCRYPT));
        out->b_size = 0;
        return -1;
    }

    out->b_size = keysize;
    return ret;
}

/* Generate random n bytes to arr */
int gen_rand_byte(struct buffer *arr, size_t n) {
    if (M_FAIL == inc_buffer_if_not_enough(arr, n)) {
        return -1;
    }

    int fd = open("/dev/random", O_RDONLY);
    if (fd == -1) {
        log_fatal(mc_err_getstr(M_ERR_SECRETKEY));
        return -1;
    }

    ssize_t nbytes = read(fd, arr->b_data, n);
    arr->b_size += nbytes;
    arr->b_next += nbytes;
    close(fd);
    return nbytes;
}

void openssl_load_err_str() {
    ERR_load_crypto_strings();
}

/* Create cipher aes/cfb8 context with iv and key
* and encrypt if enc is 1 otherwise decrypt
*/
EVP_CIPHER_CTX *aes_cipher_init(const char *key, const char *iv, int enc) {
    int ret;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    ret = EVP_CipherInit(ctx, EVP_aes_128_cfb8(), key, iv, enc);

    if (ret == NULL) {
        log_fatal(mc_err_getstr(M_ERR_CIPHER), ERR_error_string(ERR_get_error(), 0));
        return NULL;
    }
    return ctx;
}

/* Decrypt one byte using cipher context */
int aes_cipher_update_u8(EVP_CIPHER_CTX *ctx, uint8_t val, uint8_t *out) {
    int outl;
    if (!EVP_CipherUpdate(ctx, out, &outl, &val, 1)) {
        log_fatal(mc_err_getstr(M_ERR_ENCRYPT), ERR_error_string(ERR_get_error(), 0));
        return -1;
    }
    return outl;
}

/* Decrypt data from in to out using cipher context */
int aes_cipher_update(EVP_CIPHER_CTX *ctx, struct buffer *in, struct buffer *out) {
    int outl;
    if (!EVP_CipherUpdate(ctx, out->b_data, &outl, in->b_data, in->b_size)) {
        log_fatal(mc_err_getstr(M_ERR_ENCRYPT), ERR_error_string(ERR_get_error(), 0));
        out->b_size = 0;
        return -1;
    }
    out->b_size = outl;
    return outl;
}

void aes_cipher_free(EVP_CIPHER_CTX *ctx) {
    // EVP_CIPHER_CTX_clean(ctx);
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
}
