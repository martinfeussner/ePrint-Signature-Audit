#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>

#include "public_forge.h"

#if N != 1024
#error "This reproducer is pinned to n=1024"
#endif
#if Q != 59393
#error "This reproducer is pinned to q=59393"
#endif
#if B != 16383
#error "This reproducer is pinned to B=16383"
#endif
#if OMEGA != 16
#error "This reproducer is pinned to omega=16"
#endif

static uint32_t add_mod_q(uint32_t x, uint32_t y) {
    uint32_t value = x + y;
    if (value >= Q) {
        value -= Q;
    }
    return value;
}

static uint32_t sub_mod_q(uint32_t x, uint32_t y) {
    return x >= y ? x - y : x + Q - y;
}

static uint32_t add_residue(uint32_t x, uint32_t y) {
    return (x + y) % Q;
}

uint32_t glyph_centered_abs(RINGELT value) {
    uint32_t x = (uint32_t)(value % Q);
    return 2u * x <= Q ? x : Q - x;
}

static uint64_t load64_le(const unsigned char bytes[8]) {
    uint64_t value = 0;
    unsigned int i;
    for (i = 0; i < 8; ++i) {
        value |= ((uint64_t)bytes[i]) << (8u * i);
    }
    return value;
}

static int sha256_parts(const unsigned char *first,
                        size_t first_length,
                        const unsigned char *second,
                        size_t second_length,
                        unsigned char digest[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int digest_length = 0;
    int ok = 0;

    if (ctx == NULL) {
        return 0;
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        goto out;
    }
    if (first_length != 0 && EVP_DigestUpdate(ctx, first, first_length) != 1) {
        goto out;
    }
    if (second_length != 0 && EVP_DigestUpdate(ctx, second, second_length) != 1) {
        goto out;
    }
    if (EVP_DigestFinal_ex(ctx, digest, &digest_length) != 1 ||
        digest_length != 32u) {
        goto out;
    }
    ok = 1;
out:
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int hash_zero_floor_and_message(const unsigned char *message,
                                       size_t message_length,
                                       unsigned char digest[32]) {
    unsigned char zero_floor[N * Q_BYTES];
    memset(zero_floor, 0, sizeof(zero_floor));
    return sha256_parts(zero_floor, sizeof(zero_floor), message,
                        message_length, digest);
}

static int aes_ctr_next_u64(EVP_CIPHER_CTX *ctx, uint64_t *value) {
    const unsigned char zeros[8] = {0};
    unsigned char output[8];
    int output_length = 0;

    if (EVP_EncryptUpdate(ctx, output, &output_length, zeros,
                          (int)sizeof(zeros)) != 1 ||
        output_length != (int)sizeof(output)) {
        return 0;
    }
    *value = load64_le(output);
    return 1;
}

/* Independent implementation of the paper/source AES-CTR sparse encoder. */
static int encode_sparse_public(sparse_poly_t *output,
                                const unsigned char digest[32]) {
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char iv[16] = {0};
    uint64_t random_bits = 0;
    uint16_t bits_used = 0;
    uint16_t i;
    int ok = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return 0;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, digest, iv) != 1 ||
        !aes_ctr_next_u64(ctx, &random_bits)) {
        goto out;
    }

    for (i = 0; i < OMEGA; ++i) {
        for (;;) {
            uint16_t position;
            uint16_t sign;
            uint16_t j;
            int unique = 1;

            /* This is the exact bit-consumption rule in upstream encode_sparse. */
            if ((uint16_t)(bits_used + NBITS) > 64u) {
                if (!aes_ctr_next_u64(ctx, &random_bits)) {
                    goto out;
                }
                bits_used = 0;
            }
            sign = (uint16_t)(random_bits & UINT64_C(1));
            random_bits >>= 1;
            bits_used = (uint16_t)(bits_used + 1u);
            position = (uint16_t)(random_bits & ((UINT64_C(1) << NBITS) - 1u));
            random_bits >>= NBITS;
            bits_used = (uint16_t)(bits_used + NBITS);

            if (position >= N) {
                continue;
            }
            for (j = 0; j < i; ++j) {
                if (output->pos[j] == position) {
                    unique = 0;
                    break;
                }
            }
            if (unique) {
                output->pos[i] = position;
                output->sign[i] = sign;
                break;
            }
        }
    }
    ok = 1;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* Independent negacyclic product t*c in Z_q[x]/(x^N+1). */
static void sparse_mul_public(RINGELT output[N],
                              const RINGELT polynomial[N],
                              const sparse_poly_t challenge) {
    uint16_t term;
    uint16_t coefficient;

    memset(output, 0, N * sizeof(*output));
    for (term = 0; term < OMEGA; ++term) {
        for (coefficient = 0; coefficient < N; ++coefficient) {
            uint32_t raw_index =
                (uint32_t)challenge.pos[term] + (uint32_t)coefficient;
            uint16_t index = (uint16_t)(raw_index % N);
            int add = challenge.sign[term] == 1u;

            if (raw_index >= N) {
                add = !add;
            }
            if (add) {
                output[index] =
                    (RINGELT)add_mod_q((uint32_t)output[index],
                                       (uint32_t)polynomial[coefficient]);
            } else {
                output[index] =
                    (RINGELT)sub_mod_q((uint32_t)output[index],
                                       (uint32_t)polynomial[coefficient]);
            }
        }
    }
}

/* Values are residues modulo q representing 0, -(K-1), and +(K-1). */
static RINGELT select_zero_floor_z2(uint32_t u) {
    if (u < GLYPH_PARAM_D) {
        return 0;
    }
    if (u < Q - GLYPH_PARAM_L) {
        return (RINGELT)(Q - GLYPH_PARAM_L);
    }
    return (RINGELT)GLYPH_PARAM_L;
}

static RINGELT select_strict_nonzero_floor_z2(uint32_t u) {
    const RINGELT candidates[3] = {
        0,
        (RINGELT)(Q - GLYPH_PARAM_L),
        (RINGELT)GLYPH_PARAM_L
    };
    unsigned int i;

    for (i = 0; i < 3; ++i) {
        uint32_t h = add_residue(u, (uint32_t)candidates[i]);
        if (h / GLYPH_PARAM_D != 0) {
            return candidates[i];
        }
    }
    return (RINGELT)Q;
}

struct glyph_selector_report glyph_exhaustive_selector_check(void) {
    struct glyph_selector_report report;
    uint32_t u;

    memset(&report, 0, sizeof(report));
    for (u = 0; u < Q; ++u) {
        RINGELT z2 = select_zero_floor_z2(u);
        RINGELT nonzero = select_strict_nonzero_floor_z2(u);
        uint32_t h = add_residue(u, (uint32_t)z2);
        int allowed = z2 == 0 || z2 == (RINGELT)(Q - GLYPH_PARAM_L) ||
                      z2 == (RINGELT)GLYPH_PARAM_L;

        ++report.residues_tested;
        if (z2 == 0) {
            ++report.zero_branch;
        } else if (z2 == (RINGELT)(Q - GLYPH_PARAM_L)) {
            ++report.negative_branch;
        } else {
            ++report.positive_branch;
        }
        if (!allowed || glyph_centered_abs(z2) >= GLYPH_PARAM_K ||
            h / GLYPH_PARAM_D != 0) {
            ++report.selector_failures;
        }

        if (nonzero == (RINGELT)Q) {
            ++report.strict_floor_control_unreachable;
        } else if (glyph_centered_abs(nonzero) >= GLYPH_PARAM_K ||
                   add_residue(u, (uint32_t)nonzero) / GLYPH_PARAM_D == 0) {
            ++report.floor_control_failures;
        }
    }
    return report;
}

int glyph_public_forge(glp_signature_t *signature,
                       const glp_public_key_t *public_key,
                       const unsigned char *message,
                       size_t message_length,
                       struct glyph_forge_stats *stats) {
    unsigned char digest[32];
    RINGELT product[N];
    uint16_t i;

    if (signature == NULL || public_key == NULL || message == NULL ||
        stats == NULL) {
        return 0;
    }
    memset(signature, 0, sizeof(*signature));
    memset(stats, 0, sizeof(*stats));

    if (!hash_zero_floor_and_message(message, message_length, digest) ||
        !encode_sparse_public(&signature->c, digest)) {
        return 0;
    }

    sparse_mul_public(product, public_key->t, signature->c);
    for (i = 0; i < N; ++i) {
        uint32_t tc = (uint32_t)product[i];
        uint32_t u = tc == 0 ? 0 : Q - tc;
        RINGELT z2 = select_zero_floor_z2(u);
        uint32_t h = add_residue(u, (uint32_t)z2);

        signature->z1[i] = 0;
        signature->z2[i] = z2;
        if (h / GLYPH_PARAM_D == 0) {
            ++stats->zero_floor_coefficients;
        }
        if (z2 == 0) {
            ++stats->z2_zero;
        } else if (z2 == (RINGELT)(Q - GLYPH_PARAM_L)) {
            ++stats->z2_negative;
        } else if (z2 == (RINGELT)GLYPH_PARAM_L) {
            ++stats->z2_positive;
        } else {
            return 0;
        }
        if (glyph_centered_abs(z2) >= GLYPH_PARAM_K) {
            return 0;
        }
    }
    return stats->zero_floor_coefficients == N;
}

int glyph_build_floor_control(glp_signature_t *control,
                              const glp_signature_t *forgery,
                              const glp_public_key_t *public_key,
                              uint32_t *changed_index,
                              uint32_t *nonzero_floor_value) {
    const RINGELT candidates[3] = {
        0,
        (RINGELT)(Q - GLYPH_PARAM_L),
        (RINGELT)GLYPH_PARAM_L
    };
    RINGELT product[N];
    uint16_t i;
    unsigned int j;

    if (control == NULL || forgery == NULL || public_key == NULL ||
        changed_index == NULL || nonzero_floor_value == NULL) {
        return 0;
    }
    *control = *forgery;
    sparse_mul_public(product, public_key->t, forgery->c);
    for (i = 0; i < N; ++i) {
        uint32_t tc = (uint32_t)product[i];
        uint32_t u = tc == 0 ? 0 : Q - tc;
        for (j = 0; j < 3; ++j) {
            uint32_t floor_value;
            if (candidates[j] == forgery->z2[i] ||
                glyph_centered_abs(candidates[j]) >= GLYPH_PARAM_K) {
                continue;
            }
            floor_value =
                add_residue(u, (uint32_t)candidates[j]) / GLYPH_PARAM_D;
            if (floor_value != 0) {
                control->z2[i] = candidates[j];
                *changed_index = i;
                *nonzero_floor_value = floor_value;
                return 1;
            }
        }
    }
    return 0;
}
