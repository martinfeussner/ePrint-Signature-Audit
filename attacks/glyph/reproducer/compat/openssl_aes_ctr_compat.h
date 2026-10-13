#ifndef GLYPH_OPENSSL_AES_CTR_COMPAT_H
#define GLYPH_OPENSSL_AES_CTR_COMPAT_H

#include <stddef.h>

#include <openssl/aes.h>
#include <openssl/rand.h>

/*
 * GLYPH's pinned 2018 source calls the OpenSSL 1.x convenience symbol
 * AES_ctr128_encrypt().  OpenSSL 3 retains the generic CTR primitive but no
 * longer exports that wrapper.  This compatibility declaration and the
 * companion implementation restore the old API without changing any
 * upstream GLYPH source byte.
 */
void AES_ctr128_encrypt(const unsigned char *input,
                        unsigned char *output,
                        size_t length,
                        const AES_KEY *key,
                        unsigned char ivec[AES_BLOCK_SIZE],
                        unsigned char ecount_buf[AES_BLOCK_SIZE],
                        unsigned int *num);

#endif
