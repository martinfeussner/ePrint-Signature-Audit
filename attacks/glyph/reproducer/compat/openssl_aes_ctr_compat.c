#include "openssl_aes_ctr_compat.h"

#include <openssl/modes.h>

void AES_ctr128_encrypt(const unsigned char *input,
                        unsigned char *output,
                        size_t length,
                        const AES_KEY *key,
                        unsigned char ivec[AES_BLOCK_SIZE],
                        unsigned char ecount_buf[AES_BLOCK_SIZE],
                        unsigned int *num) {
    CRYPTO_ctr128_encrypt(input, output, length, key, ivec, ecount_buf, num,
                          (block128_f)AES_encrypt);
}
