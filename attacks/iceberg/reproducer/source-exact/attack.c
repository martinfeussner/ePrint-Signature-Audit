/* Exact-source diagnostic for Iceberg EXP-0001.  This intentionally includes
 * the pinned secp256k1 implementation so the source's internal coefficient
 * functions and scalar representation are the ones used in the extraction. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ENABLE_MODULE_EXTRAKEYS 1
#define ENABLE_MODULE_SCHNORRSIG 1
#define ENABLE_MODULE_MUSIG 1
#define ENABLE_MODULE_ICEBERG 1
#define ECMULT_WINDOW_SIZE 15
#define COMB_BLOCKS 43
#define COMB_TEETH 6

#include "../../../source-cache/iceberg-2026-1757/upstream/benchmark-iceberg/sources/secp256k1-kmp/native/secp256k1/src/secp256k1.c"

#define N 4
#define T 2
#define MU 3
#define NCTX 3

typedef struct exact_coeffs {
    secp256k1_scalar b0;
    secp256k1_scalar b1;
    secp256k1_scalar e;
    secp256k1_scalar a;
    secp256k1_scalar b0b1;
    secp256k1_scalar keycoef;
    int fin_parity;
    int key_negated;
} exact_coeffs;

static void fail_at(const char *what, int line) {
    fprintf(stderr, "FAIL line=%d step=%s\n", line, what);
    exit(1);
}

#define MUST(x) do { if (!(x)) fail_at(#x, __LINE__); } while (0)

static void fill32(unsigned char out[32], unsigned char tag) {
    size_t i;
    for (i = 0; i < 32; i++) out[i] = (unsigned char)(tag + 17U * (unsigned char)i);
}

static void print_scalar(const char *name, int j, const secp256k1_scalar *x) {
    unsigned char b[32];
    size_t i;
    secp256k1_scalar_get_b32(b, x);
    printf("ctx%d_%s=", j, name);
    for (i = 0; i < sizeof(b); i++) printf("%02x", b[i]);
    printf("\n");
}

static void scalar_sub(secp256k1_scalar *r, const secp256k1_scalar *a,
                       const secp256k1_scalar *b) {
    secp256k1_scalar nb;
    secp256k1_scalar_negate(&nb, b);
    secp256k1_scalar_add(r, a, &nb);
    secp256k1_scalar_clear(&nb);
}

/* Gauss-Jordan solve of a 3 by 3 scalar matrix. */
static int solve3(secp256k1_scalar out[3], const secp256k1_scalar in_a[3][3],
                  const secp256k1_scalar in_b[3]) {
    secp256k1_scalar m[3][4], inv, factor, prod, tmp;
    int row, col, k, pivot;
    for (row = 0; row < 3; row++) {
        for (col = 0; col < 3; col++) m[row][col] = in_a[row][col];
        m[row][3] = in_b[row];
    }
    for (col = 0; col < 3; col++) {
        pivot = -1;
        for (row = col; row < 3; row++) {
            if (!secp256k1_scalar_is_zero(&m[row][col])) { pivot = row; break; }
        }
        if (pivot < 0) return 0;
        if (pivot != col) {
            for (k = col; k < 4; k++) {
                tmp = m[col][k]; m[col][k] = m[pivot][k]; m[pivot][k] = tmp;
            }
        }
        secp256k1_scalar_inverse_var(&inv, &m[col][col]);
        for (k = col; k < 4; k++) secp256k1_scalar_mul(&m[col][k], &m[col][k], &inv);
        for (row = 0; row < 3; row++) {
            if (row == col) continue;
            factor = m[row][col];
            for (k = col; k < 4; k++) {
                secp256k1_scalar_mul(&prod, &factor, &m[col][k]);
                scalar_sub(&m[row][k], &m[row][k], &prod);
            }
        }
    }
    for (row = 0; row < 3; row++) out[row] = m[row][3];
    return 1;
}

/* This is the coefficient path from secp256k1_iceberg_session_values, split
 * into named values for the experiment log. */
static int get_exact_coeffs(const secp256k1_context *ctx, exact_coeffs *c,
                            const secp256k1_iceberg_aggnonce *aggnonce,
                            const secp256k1_pubkey *group_pk,
                            const secp256k1_musig_keyagg_cache *keyagg_cache,
                            const unsigned char msg32[32],
                            const secp256k1_musig_aggnonce *cosigner_aggnonce) {
    secp256k1_keyagg_cache_internal cache_i;
    secp256k1_ge group_pts[2], cosigner_pts[2], total[2], pk;
    secp256k1_gej acc;
    secp256k1_scalar check_b0b1, check_keycoef;
    unsigned char agg_pk32[32], fin_nonce[32];
    int check_parity, i;

    if (!secp256k1_keyagg_cache_load(ctx, &cache_i, keyagg_cache) ||
        !secp256k1_pubkey_load(ctx, &pk, group_pk) ||
        !secp256k1_iceberg_aggnonce_load(ctx, group_pts, aggnonce) ||
        !secp256k1_musig_aggnonce_load(ctx, cosigner_pts, cosigner_aggnonce)) return 0;
    secp256k1_iceberg_noncecoef(ctx, &c->b1, group_pts, &pk);
    if (!secp256k1_iceberg_publish_nonce(total, group_pts, &c->b1)) return 0;
    for (i = 0; i < 2; i++) {
        secp256k1_gej_set_ge(&acc, &total[i]);
        secp256k1_gej_add_ge_var(&acc, &acc, &cosigner_pts[i], NULL);
        secp256k1_ge_set_gej(&total[i], &acc);
    }
    secp256k1_fe_get_b32(agg_pk32, &cache_i.pk.x);
    secp256k1_musig_nonce_process_internal(ctx, &c->fin_parity, fin_nonce,
                                           &c->b0, total, agg_pk32, msg32);
    secp256k1_schnorrsig_challenge(secp256k1_get_hash_context(ctx), &c->e,
                                   fin_nonce, msg32, 32, agg_pk32);
    secp256k1_iceberg_noncecoef(ctx, &c->b1, group_pts, &pk);
    secp256k1_scalar_mul(&c->b0b1, &c->b0, &c->b1);
    secp256k1_musig_keyaggcoef(secp256k1_get_hash_context(ctx), &c->a, &cache_i, &pk);
    c->keycoef = c->e;
    secp256k1_scalar_mul(&c->keycoef, &c->keycoef, &c->a);
    c->key_negated = secp256k1_fe_is_odd(&cache_i.pk.y) != cache_i.parity_acc;
    if (c->key_negated) secp256k1_scalar_negate(&c->keycoef, &c->keycoef);

    if (!secp256k1_iceberg_session_values(ctx, &check_b0b1, &check_keycoef,
                                          &check_parity, aggnonce, group_pk,
                                          keyagg_cache, msg32,
                                          cosigner_aggnonce)) return 0;
    return secp256k1_scalar_eq(&check_b0b1, &c->b0b1) &&
           secp256k1_scalar_eq(&check_keycoef, &c->keycoef) &&
           check_parity == c->fin_parity;
}

static int pubkeys_equal(const secp256k1_context *ctx,
                         const secp256k1_pubkey *a,
                         const secp256k1_pubkey *b) {
    unsigned char sa[33], sb[33];
    size_t la = sizeof(sa), lb = sizeof(sb);
    return secp256k1_ec_pubkey_serialize(ctx, sa, &la, a, SECP256K1_EC_COMPRESSED) &&
           secp256k1_ec_pubkey_serialize(ctx, sb, &lb, b, SECP256K1_EC_COMPRESSED) &&
           la == lb && memcmp(sa, sb, la) == 0;
}

int main(void) {
    secp256k1_context *ctx;
    secp256k1_iceberg_share shares[N];
    secp256k1_iceberg_share *share_ptrs[N];
    secp256k1_iceberg_pubshare pubshares[N];
    const secp256k1_iceberg_pubshare *group_pubshare_ptrs[MU];
    secp256k1_iceberg_pubnonce honest_nonces[MU];
    const secp256k1_iceberg_pubnonce *honest_nonce_ptrs[MU];
    secp256k1_pubkey group_pk, cosigner_pk, recovered_pk;
    const secp256k1_pubkey *outer_keys[2];
    secp256k1_xonly_pubkey aggregate_xonly;
    secp256k1_musig_keyagg_cache keyagg_cache;
    secp256k1_musig_pubnonce group_pubnonce, cosigner_pubnonce[NCTX];
    secp256k1_musig_secnonce cosigner_secnonce[NCTX];
    secp256k1_musig_aggnonce cosigner_aggnonce[NCTX], full_aggnonce;
    secp256k1_iceberg_aggnonce iceberg_aggnonce;
    secp256k1_iceberg_partial_sig corrupt_psig[NCTX], honest_psig[NCTX];
    const secp256k1_iceberg_partial_sig *pair[2];
    secp256k1_musig_partial_sig group_psig[NCTX], cosigner_psig[NCTX];
    const secp256k1_musig_partial_sig *outer_psigs[2];
    secp256k1_musig_session sessions[NCTX];
    exact_coeffs coeff[NCTX];
    secp256k1_scalar mat[NCTX][3], rhs[NCTX], sol[3], repeated[3][3];
    unsigned char seed[32], sid[32], msg[32], fresh_msg[32], mutated_msg[32];
    unsigned char cosigner_sk[32], cosigner_rand[NCTX][32];
    unsigned char final_sig[NCTX][64], recovered_sk[32];
    secp256k1_keypair cosigner_keypair, recovered_keypair;
    unsigned char serialized_nonces[NCTX][66];
    int query_count[N] = {0, 0, 0, 0};
    int observed_verify_count = 0;
    int j, i, matrix_ok, repeated_ok, recovered_match;

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    MUST(ctx != NULL);
    fill32(seed, 0x11); fill32(sid, 0x42); fill32(msg, 0x73);
    fill32(fresh_msg, 0xa4); memcpy(mutated_msg, fresh_msg, 32); mutated_msg[0] ^= 1;
    memset(cosigner_sk, 0, 32); cosigner_sk[31] = 0x23;

    for (i = 0; i < N; i++) share_ptrs[i] = &shares[i];
    MUST(secp256k1_iceberg_shares_gen(ctx, share_ptrs, N, T, seed));
    for (i = 0; i < N; i++) MUST(secp256k1_iceberg_pubshare_gen(ctx, &pubshares[i], &shares[i], NULL));
    /* Honest participants 2,3,4 provide the 2t-1 public/nonce quorum. */
    for (i = 0; i < MU; i++) group_pubshare_ptrs[i] = &pubshares[i + 1];
    MUST(secp256k1_iceberg_pubkey_agg(ctx, &group_pk, group_pubshare_ptrs, MU, N, T));

    MUST(secp256k1_ec_pubkey_create(ctx, &cosigner_pk, cosigner_sk));
    MUST(secp256k1_keypair_create(ctx, &cosigner_keypair, cosigner_sk));
    outer_keys[0] = &group_pk; outer_keys[1] = &cosigner_pk;
    MUST(secp256k1_musig_pubkey_agg(ctx, &aggregate_xonly, &keyagg_cache, outer_keys, 2));
    MUST(secp256k1_iceberg_keyagg_check(ctx, &keyagg_cache, outer_keys, 2, &group_pk));

    /* Exact PreRound schedule: every honest member once, common SID. */
    for (i = 0; i < MU; i++) {
        MUST(secp256k1_iceberg_nonce_gen(ctx, &honest_nonces[i], &shares[i + 1], NULL, sid));
        honest_nonce_ptrs[i] = &honest_nonces[i];
    }
    MUST(secp256k1_iceberg_nonce_agg(ctx, &group_pubnonce, &iceberg_aggnonce,
                                     honest_nonce_ptrs, MU, N, T, &group_pk));

    for (j = 0; j < NCTX; j++) {
        const secp256k1_musig_pubnonce *one_cosigner[1];
        const secp256k1_musig_pubnonce *both_nonces[2];
        secp256k1_scalar eps;

        fill32(cosigner_rand[j], (unsigned char)(0xc1 + 19 * j));
        MUST(secp256k1_musig_nonce_gen(ctx, &cosigner_secnonce[j], &cosigner_pubnonce[j],
                                      cosigner_rand[j], cosigner_sk, &cosigner_pk,
                                      msg, &keyagg_cache, NULL));
        MUST(secp256k1_musig_pubnonce_serialize(ctx, serialized_nonces[j], &cosigner_pubnonce[j]));
        one_cosigner[0] = &cosigner_pubnonce[j];
        MUST(secp256k1_musig_nonce_agg(ctx, &cosigner_aggnonce[j], one_cosigner, 1));

        /* Corrupt member 1 is local; honest member 2+j is queried once. */
        MUST(secp256k1_iceberg_partial_sign(ctx, &corrupt_psig[j], &shares[0], NULL,
                                           sid, honest_nonce_ptrs, MU, &group_pk,
                                           &keyagg_cache, msg, &cosigner_aggnonce[j]));
        MUST(secp256k1_iceberg_partial_sign(ctx, &honest_psig[j], &shares[j + 1], NULL,
                                           sid, honest_nonce_ptrs, MU, &group_pk,
                                           &keyagg_cache, msg, &cosigner_aggnonce[j]));
        query_count[j + 1]++;
        MUST(secp256k1_iceberg_partial_sig_verify(ctx, &corrupt_psig[j], &pubshares[0],
                                                  honest_nonce_ptrs, MU, N, T, &group_pk,
                                                  &keyagg_cache, msg, &cosigner_aggnonce[j]));
        MUST(secp256k1_iceberg_partial_sig_verify(ctx, &honest_psig[j], &pubshares[j + 1],
                                                  honest_nonce_ptrs, MU, N, T, &group_pk,
                                                  &keyagg_cache, msg, &cosigner_aggnonce[j]));
        pair[0] = &corrupt_psig[j]; pair[1] = &honest_psig[j];
        MUST(secp256k1_iceberg_partial_sig_agg(ctx, &group_psig[j], pair, 2, N, T));
        MUST(secp256k1_musig_partial_sig_load(ctx, &rhs[j], &group_psig[j]));
        MUST(get_exact_coeffs(ctx, &coeff[j], &iceberg_aggnonce, &group_pk,
                              &keyagg_cache, msg, &cosigner_aggnonce[j]));

        secp256k1_scalar_set_int(&eps, 1);
        if (coeff[j].fin_parity) secp256k1_scalar_negate(&eps, &eps);
        mat[j][0] = eps;
        secp256k1_scalar_mul(&mat[j][1], &eps, &coeff[j].b0b1);
        mat[j][2] = coeff[j].keycoef;

        /* Every observed context also completes to an ordinary valid BIP340 signature. */
        both_nonces[0] = &group_pubnonce; both_nonces[1] = &cosigner_pubnonce[j];
        MUST(secp256k1_musig_nonce_agg(ctx, &full_aggnonce, both_nonces, 2));
        MUST(secp256k1_musig_nonce_process(ctx, &sessions[j], &full_aggnonce, msg, &keyagg_cache));
        MUST(secp256k1_musig_partial_sign(ctx, &cosigner_psig[j], &cosigner_secnonce[j],
                                         &cosigner_keypair, &keyagg_cache, &sessions[j]));
        outer_psigs[0] = &group_psig[j]; outer_psigs[1] = &cosigner_psig[j];
        MUST(secp256k1_musig_partial_sig_agg(ctx, final_sig[j], &sessions[j], outer_psigs, 2));
        MUST(secp256k1_schnorrsig_verify(ctx, final_sig[j], msg, 32, &aggregate_xonly));
        observed_verify_count++;
    }

    MUST(memcmp(serialized_nonces[0], serialized_nonces[1], 66) != 0);
    MUST(memcmp(serialized_nonces[0], serialized_nonces[2], 66) != 0);
    MUST(memcmp(serialized_nonces[1], serialized_nonces[2], 66) != 0);
    matrix_ok = solve3(sol, mat, rhs);
    MUST(matrix_ok);
    for (i = 0; i < 3; i++) {
        repeated[i][0] = mat[0][0]; repeated[i][1] = mat[0][1]; repeated[i][2] = mat[0][2];
    }
    repeated_ok = solve3(sol, repeated, rhs);
    MUST(!repeated_ok);

    /* solve3 above wrote sol only on success; solve the real matrix again after control. */
    MUST(solve3(sol, mat, rhs));
    secp256k1_scalar_get_b32(recovered_sk, &sol[2]);
    MUST(secp256k1_ec_seckey_verify(ctx, recovered_sk));
    MUST(secp256k1_ec_pubkey_create(ctx, &recovered_pk, recovered_sk));
    recovered_match = pubkeys_equal(ctx, &recovered_pk, &group_pk);
    MUST(recovered_match);
    MUST(secp256k1_keypair_create(ctx, &recovered_keypair, recovered_sk));

    /* Fresh ordinary MuSig2 forgery: recovered group key + attacker cosigner;
     * no call involving an honest Iceberg share occurs below this point. */
    {
        secp256k1_musig_secnonce fresh_secnonce[2];
        secp256k1_musig_pubnonce fresh_pubnonce[2];
        const secp256k1_musig_pubnonce *fresh_nonce_ptrs[2];
        secp256k1_musig_aggnonce fresh_aggnonce;
        secp256k1_musig_session fresh_session;
        secp256k1_musig_partial_sig fresh_psig[2];
        const secp256k1_musig_partial_sig *fresh_psig_ptrs[2];
        unsigned char rand0[32], rand1[32], forged_sig[64];
        int fresh_verify, mutation_reject;
        fill32(rand0, 0xe2); fill32(rand1, 0xf3);
        MUST(secp256k1_musig_nonce_gen(ctx, &fresh_secnonce[0], &fresh_pubnonce[0],
                                      rand0, recovered_sk, &group_pk, fresh_msg,
                                      &keyagg_cache, NULL));
        MUST(secp256k1_musig_nonce_gen(ctx, &fresh_secnonce[1], &fresh_pubnonce[1],
                                      rand1, cosigner_sk, &cosigner_pk, fresh_msg,
                                      &keyagg_cache, NULL));
        fresh_nonce_ptrs[0] = &fresh_pubnonce[0]; fresh_nonce_ptrs[1] = &fresh_pubnonce[1];
        MUST(secp256k1_musig_nonce_agg(ctx, &fresh_aggnonce, fresh_nonce_ptrs, 2));
        MUST(secp256k1_musig_nonce_process(ctx, &fresh_session, &fresh_aggnonce,
                                           fresh_msg, &keyagg_cache));
        MUST(secp256k1_musig_partial_sign(ctx, &fresh_psig[0], &fresh_secnonce[0],
                                         &recovered_keypair, &keyagg_cache, &fresh_session));
        MUST(secp256k1_musig_partial_sign(ctx, &fresh_psig[1], &fresh_secnonce[1],
                                         &cosigner_keypair, &keyagg_cache, &fresh_session));
        fresh_psig_ptrs[0] = &fresh_psig[0]; fresh_psig_ptrs[1] = &fresh_psig[1];
        MUST(secp256k1_musig_partial_sig_agg(ctx, forged_sig, &fresh_session,
                                            fresh_psig_ptrs, 2));
        fresh_verify = secp256k1_schnorrsig_verify(ctx, forged_sig, fresh_msg, 32, &aggregate_xonly);
        mutation_reject = !secp256k1_schnorrsig_verify(ctx, forged_sig, mutated_msg, 32, &aggregate_xonly);
        MUST(fresh_verify && mutation_reject);

        printf("profile=ICEBERG-SECP256K1-T2-N4-MU3-NU2-DEPTH2-BIP327-BIP340-SID32-ARTIFACT-B2F87CB\n");
        printf("trusted_dealer=1\ncorrupt_members=1\n");
        printf("honest_preround_queries=3\nhonest_sign_queries=3\n");
        for (i = 1; i < N; i++) printf("honest_member_%d_sign_queries=%d\n", i + 1, query_count[i]);
        printf("same_sid=1\nsame_message=1\ndistinct_outer_contexts=1\n");
        printf("fixed_cosigner_key=1\ngroup_first=1\nuntweaked=1\n");
        printf("changed_message_rejected_by_game_rule=1\n");
        printf("unchanged_context_rank_deficient=%d\n", !repeated_ok);
        printf("matrix_invertible=%d\n", matrix_ok);
        printf("recovered_group_key_matches=%d\n", recovered_match);
        printf("observed_context_final_verify_count=%d\n", observed_verify_count);
        printf("fresh_message_never_queried=%d\n", memcmp(fresh_msg, msg, 32) != 0);
        printf("fresh_honest_sign_queries=0\n");
        printf("fresh_bip340_verify=%d\n", fresh_verify);
        printf("fresh_mutated_message_reject=%d\n", mutation_reject);
    }
    for (j = 0; j < NCTX; j++) {
        printf("ctx%d_fin_parity=%d\nctx%d_eps_sign=%d\nctx%d_key_parity_sign=%d\n",
               j, coeff[j].fin_parity, j, coeff[j].fin_parity ? -1 : 1,
               j, coeff[j].key_negated ? -1 : 1);
        print_scalar("b1", j, &coeff[j].b1);
        print_scalar("b0", j, &coeff[j].b0);
        print_scalar("b0b1", j, &coeff[j].b0b1);
        print_scalar("challenge_e", j, &coeff[j].e);
        print_scalar("keyagg_a", j, &coeff[j].a);
        print_scalar("keycoef_e_a_gamma", j, &coeff[j].keycoef);
        print_scalar("row_nonce1", j, &mat[j][0]);
        print_scalar("row_nonce2", j, &mat[j][1]);
        print_scalar("row_group_key", j, &mat[j][2]);
        print_scalar("rhs_group_partial", j, &rhs[j]);
    }
    print_scalar("recovered_group_secret", 0, &sol[2]);
    printf("result=PASS\n");
    secp256k1_context_destroy(ctx);
    return 0;
}

