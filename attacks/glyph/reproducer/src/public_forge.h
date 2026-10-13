#ifndef GLYPH_PUBLIC_FORGE_H
#define GLYPH_PUBLIC_FORGE_H

#include <stddef.h>
#include <stdint.h>

#include "glp.h"

/* The complete recommended row in ePrint 2017/766, Section 4. */
#define GLYPH_PARAM_M 2048u
#define GLYPH_PARAM_K ((uint32_t)B - (uint32_t)OMEGA)
#define GLYPH_PARAM_L (GLYPH_PARAM_K - 1u)
#define GLYPH_PARAM_D (2u * GLYPH_PARAM_K + 1u)

struct glyph_forge_stats {
    uint32_t zero_floor_coefficients;
    uint32_t z2_zero;
    uint32_t z2_negative;
    uint32_t z2_positive;
};

struct glyph_selector_report {
    uint32_t residues_tested;
    uint32_t zero_branch;
    uint32_t negative_branch;
    uint32_t positive_branch;
    uint32_t selector_failures;
    uint32_t strict_floor_control_unreachable;
    uint32_t floor_control_failures;
};

/*
 * Public-only attack API.  The function has no signing-key argument and makes
 * no signing-oracle call.  It independently implements the public hash,
 * challenge encoding, and sparse product needed by the attack.
 */
int glyph_public_forge(glp_signature_t *signature,
                       const glp_public_key_t *public_key,
                       const unsigned char *message,
                       size_t message_length,
                       struct glyph_forge_stats *stats);

/* Exhaust the selector over every residue u in [0,q). */
struct glyph_selector_report glyph_exhaustive_selector_check(void);

/* Build an in-bound response mutation whose verifier floor is nonzero. */
int glyph_build_floor_control(glp_signature_t *control,
                              const glp_signature_t *forgery,
                              const glp_public_key_t *public_key,
                              uint32_t *changed_index,
                              uint32_t *nonzero_floor_value);

uint32_t glyph_centered_abs(RINGELT value);

#endif
