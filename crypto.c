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
static char *PEM_END   = "-----END PUBLIC KEY-----";

RSA* PEM_load_pubkey_from_str(const char* publicKeyStr) {
  // A BIO is an I/O abstraction (Byte I/O?)

  // BIO_new_mem_buf: Create a read-only bio buf with data
  // in string passed. -1 means string is null terminated,
  // so BIO_new_mem_buf can find the dataLen itself.
  // Since BIO_new_mem_buf will be READ ONLY, it's fine that publicKeyStr is const.
  BIO* bio = BIO_new_mem_buf( (void*)publicKeyStr, -1 ) ; // -1: assume string is null terminated

  BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL ) ; // NO NL

  // Load the RSA key from the BIO
  RSA* rsaPubKey = PEM_read_bio_RSA_PUBKEY( bio, NULL, NULL, NULL ) ;
  if( !rsaPubKey )
    printf( "ERROR: Could not load PUBLIC KEY!  PEM_read_bio_RSA_PUBKEY FAILED: %s\n", ERR_error_string( ERR_get_error(), NULL ) ) ;

  BIO_free( bio ) ;
  return rsaPubKey ;
}

RSA *DER_load_pubkey_from_str(struct bytearray *arr) {
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

int RSA_encrypt_with_pubkey(RSA *rsa, struct bytearray *in, struct bytearray *out) {
    size_t keysize = RSA_size(rsa);
    // size_t len = ceil((double)in->b_size / (double)keysize) * keysize;
    
    if (out->b_allocsize < keysize 
        && inc_bytearray(out, keysize - out->b_allocsize) == NULL) {
        fputs("Fail to malloc", stderr);
        return 0;
    }
    int nbytes = RSA_public_encrypt(in->b_size, (unsigned char *)in->b_data, (unsigned char *)out->b_data, rsa, RSA_PKCS1_PADDING);
    out->b_size = nbytes;
    return nbytes;
}

int gen_rand_byte(struct bytearray *arr, size_t n) {
    int fd = open("/dev/random", O_RDONLY);
    ssize_t nbytes = read(fd, arr->b_data, n);
    arr->b_size = nbytes;
    close(fd);
    return nbytes;
}

void openssl_load_err_str() {
    ERR_load_crypto_strings();
}
