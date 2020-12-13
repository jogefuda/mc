#ifndef __CRYPTO_H
#define __CRYPTO_H

#include "utils.h"
#include "minecraft.h"
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

/* rsa function */
RSA *DER_load_pubkey_from_str(struct buffer *arr);
int RSA_encrypt_with_pubkey(RSA *rsa, struct buffer *in, struct buffer *out);

/* aes/cfb8 function */
EVP_CIPHER_CTX *aes_cipher_init(const char *key, const char *iv, int enc);
int aes_cipher_update_u8(EVP_CIPHER_CTX *ctx, uint8_t val, uint8_t *out);
int aes_cipher_update(EVP_CIPHER_CTX * ctx, struct buffer *in, struct buffer *out);
void aes_cipher_free(EVP_CIPHER_CTX *ctx);

void openssl_load_err_str();
int gen_rand_byte(struct buffer *arr, size_t n);

#endif // __CRYPTO_H
