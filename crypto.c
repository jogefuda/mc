#include "crypto.h"
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

RSA* PEM_load_pubkey_from_str(const char* publicKeyStr) {
    // A BIO is an I/O abstraction (Byte I/O?)

    // BIO_new_mem_buf: Create a read-only bio buf with data
    // in string passed. -1 means string is null terminated,
    // so BIO_new_mem_buf can find the dataLen itself.
    // Since BIO_new_mem_buf will be READ ONLY, it's fine that publicKeyStr is const.
    BIO* bio = BIO_new_mem_buf((void*)publicKeyStr, -1); // -1: assume string is null terminated

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // NO NL

    // Load the RSA key from the BIO
    RSA* rsaPubKey = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if (!rsaPubKey)
        printf("ERROR: Could not load PUBLIC KEY!  PEM_read_bio_RSA_PUBKEY FAILED: %s\n", ERR_error_string(ERR_get_error(), NULL));

    BIO_free(bio);
    return rsaPubKey;
}

RSA *DER_load_pubkey_from_str(struct buffer *arr) {
    gnutls_datum_t raw, b64;
    raw.data = arr->b_data;
    raw.size = arr->b_size;
    gnutls_base64_encode2(&raw, &b64);

    char *outkey = malloc(strlen(PEM_START) + b64.size + strlen(PEM_END) + 1);
    sprintf(outkey, "%s\n%s\n%s", PEM_START, b64.data, PEM_END);

    RSA *rsa = PEM_load_pubkey_from_str(outkey);
    gnutls_free(b64.data);
    free(outkey);
    return rsa;
}

int RSA_encrypt_with_pubkey(RSA *rsa, struct buffer *in, struct buffer *out) {
    int ret;
    size_t keysize = RSA_size(rsa);
    if (!inc_buffer_if_not_enough(out, keysize)) {
        // TODO: error handle
        fputs("Fail to malloc", stderr);
        return 0;
    }

    ret = RSA_public_encrypt(in->b_size, (unsigned char *)in->b_data, (unsigned char *)out->b_next, rsa, RSA_PKCS1_PADDING);
    out->b_size += keysize;

    if (ret == -1) {
        out->b_size = 0;
        return 0;
        // TODO: error handle
    }

    out->b_size = keysize;
    return 1;
}

int gen_rand_byte(struct buffer *arr, size_t n) {
    inc_buffer_if_not_enough(arr, n);
    // TODO: error handle

    int fd = open("/dev/random", O_RDONLY);
    ssize_t nbytes = read(fd, arr->b_data, n);
    arr->b_size += nbytes;
    arr->b_next += nbytes;
    close(fd);
    return nbytes;
}

void openssl_load_err_str() {
    ERR_load_crypto_strings();
}

EVP_CIPHER_CTX *aes_cipher_init(const char *key, const char *iv, int enc) {
    int ret;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    ret = EVP_CipherInit(ctx, EVP_aes_128_cfb8(), key, iv, enc);

    if (!ret) {
        printf("%s\n", ERR_error_string(ERR_get_error(), 0));
        return NULL;
    }
    return ctx;
}

void aes_cipher_update_u8(EVP_CIPHER_CTX *ctx, uint8_t val, uint8_t *out) {
    int outl;
    if (!EVP_CipherUpdate(ctx, out, &outl, &val, 1)) {
        printf("%s\n", ERR_error_string(ERR_get_error(), 0));
        return;
    }
}

void aes_cipher_update(EVP_CIPHER_CTX *ctx, struct buffer *in, struct buffer *out) {
    int outl;
    if (!EVP_CipherUpdate(ctx, out->b_data, &outl, in->b_data, in->b_size)) {
        printf("%s\n", ERR_error_string(ERR_get_error(), 0));
        out->b_size = 0;
        return;
    }
    out->b_size = outl;
}

void aes_clean(EVP_CIPHER_CTX *ctx) {
    // EVP_CIPHER_CTX_clean(ctx);
    EVP_CIPHER_CTX_free(ctx);
}
