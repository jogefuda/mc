#ifndef __CRYPTO_H
#define __CRYPTO_H

#include "utils.h"
#include <openssl/rsa.h>

RSA *PEM_load_pubkey_from_str(const char* publicKeyStr);
RSA *DER_load_pubkey_from_str(struct buffer *arr);
int RSA_encrypt_with_pubkey(RSA *rsa, struct buffer *in, struct buffer *out);
int gen_rand_byte(struct buffer *arr, size_t n);
void openssl_load_err_str();

#endif // __CRYPTO_H
