#ifndef __HASH_H
#define __HASH_H

#include <openssl/evp.h>

EVP_MD_CTX *mc_hash_init(EVP_MD_CTX *ctx);
int mc_hash_update(EVP_MD_CTX *ctx, const char *data, size_t len);
int mc_hash_final(EVP_MD_CTX *ctx, char *buf, unsigned int *len);
void mc_hash_clean(EVP_MD_CTX *ctx);

#endif // __HASH_H
