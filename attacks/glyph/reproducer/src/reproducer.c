#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>

#include "glp.h"
#include "public_forge.h"

#define MESSAGE_BYTES 48u
#define MAX_TRIALS 100000u
#define CONTROL_COUNT 8u

enum control_index {
    CONTROL_CHANGED_MESSAGE = 0,
    CONTROL_TRUNCATED_MESSAGE,
    CONTROL_EXTENDED_MESSAGE,
    CONTROL_CHANGED_CHALLENGE_SIGN,
    CONTROL_CHANGED_CHALLENGE_POSITION,
    CONTROL_CHANGED_FLOOR,
    CONTROL_Z1_BOUND,
    CONTROL_Z2_BOUND
};

static const char *const CONTROL_NAMES[CONTROL_COUNT] = {
    "changed_message",
    "truncated_message",
    "extended_message",
    "changed_challenge_sign",
    "changed_challenge_position",
    "changed_floor",
    "out_of_range_z1",
    "out_of_range_z2"
};

struct counters {
    uint32_t completed_trials;
    uint32_t forge_accepts;
    uint32_t control_rejects[CONTROL_COUNT];
    uint64_t zero_floor_coefficients;
    uint64_t z2_zero;
    uint64_t z2_negative;
    uint64_t z2_positive;
};

static void usage(const char *program) {
    fprintf(stderr,
            "Usage: %s --mode quick|full --trials N --summary PATH "
            "--trials-csv PATH\n",
            program);
}

static int parse_u32(const char *text, uint32_t *value) {
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed == 0 ||
        parsed > MAX_TRIALS) {
        return 0;
    }
    *value = (uint32_t)parsed;
    return 1;
}

static int host_is_little_endian(void) {
    const uint16_t one = 1;
    return *((const unsigned char *)&one) == 1u;
}

static double monotonic_seconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1.0;
    }
    return (double)now.tv_sec + (double)now.tv_nsec / 1000000000.0;
}

static int sha256_bytes(const unsigned char *data,
                        size_t length,
                        unsigned char digest[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int digest_length = 0;
    int ok = 0;

    if (ctx == NULL) {
        return 0;
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        (length != 0 && EVP_DigestUpdate(ctx, data, length) != 1) ||
        EVP_DigestFinal_ex(ctx, digest, &digest_length) != 1 ||
        digest_length != 32u) {
        goto out;
    }
    ok = 1;
out:
    EVP_MD_CTX_free(ctx);
    return ok;
}

static void hex_encode(const unsigned char *bytes,
                       size_t length,
                       char *output) {
    static const char alphabet[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < length; ++i) {
        output[2u * i] = alphabet[bytes[i] >> 4];
        output[2u * i + 1u] = alphabet[bytes[i] & 0x0fu];
    }
    output[2u * length] = '\0';
}

static void store16_le(unsigned char output[2], uint32_t value) {
    output[0] = (unsigned char)(value & 0xffu);
    output[1] = (unsigned char)((value >> 8) & 0xffu);
}

static int canonical_public_key(const glp_public_key_t *public_key,
                                unsigned char output[2 * N]) {
    uint16_t i;
    for (i = 0; i < N; ++i) {
        uint32_t coefficient = (uint32_t)public_key->t[i];
        if (coefficient >= Q) {
            return 0;
        }
        store16_le(output + 2u * i, coefficient);
    }
    return 1;
}

static int canonical_signature(const glp_signature_t *signature,
                               unsigned char output[4 * N + 4 * OMEGA]) {
    size_t offset = 0;
    uint16_t i;

    for (i = 0; i < N; ++i) {
        if ((uint32_t)signature->z1[i] >= Q) {
            return 0;
        }
        store16_le(output + offset, (uint32_t)signature->z1[i]);
        offset += 2u;
    }
    for (i = 0; i < N; ++i) {
        if ((uint32_t)signature->z2[i] >= Q) {
            return 0;
        }
        store16_le(output + offset, (uint32_t)signature->z2[i]);
        offset += 2u;
    }
    for (i = 0; i < OMEGA; ++i) {
        store16_le(output + offset, signature->c.pos[i]);
        offset += 2u;
        store16_le(output + offset, signature->c.sign[i]);
        offset += 2u;
    }
    return offset == 4u * N + 4u * OMEGA;
}

static int digest_seen(const unsigned char *digests,
                       uint32_t count,
                       const unsigned char candidate[32]) {
    uint32_t i;
    for (i = 0; i < count; ++i) {
        if (CRYPTO_memcmp(digests + 32u * i, candidate, 32u) == 0) {
            return 1;
        }
    }
    return 0;
}

static int unused_challenge_position(const sparse_poly_t *challenge) {
    uint16_t candidate;
    for (candidate = 0; candidate < N; ++candidate) {
        uint16_t i;
        int used = 0;
        for (i = 0; i < OMEGA; ++i) {
            if (challenge->pos[i] == candidate) {
                used = 1;
                break;
            }
        }
        if (!used) {
            return (int)candidate;
        }
    }
    return -1;
}

static int write_summary(const char *path,
                         const char *mode,
                         uint32_t requested_trials,
                         const struct counters *counts,
                         const struct glyph_selector_report *selector,
                         double runtime_seconds,
                         long peak_rss_kib,
                         int passed) {
    FILE *file = fopen(path, "wb");
    uint32_t total_control_rejects = 0;
    unsigned int i;
    int ok;

    if (file == NULL) {
        perror(path);
        return 0;
    }
    for (i = 0; i < CONTROL_COUNT; ++i) {
        total_control_rejects += counts->control_rejects[i];
    }

    ok = fprintf(
             file,
             "{\n"
             "  \"schema\": \"glyph-public-reproducer-v1\",\n"
             "  \"status\": \"%s\",\n"
             "  \"mode\": \"%s\",\n"
             "  \"scheme\": \"GLYPH\",\n"
             "  \"target\": {\"eprint\": \"2017/766 final v3\", \"source_commit\": \"74b96d691391f687fe8f91e1d5cb3c251762d7cc\", \"source_tree\": \"2ae8eec4b23dc57fc816c8935da8c2a59a753196\"},\n"
             "  \"attack\": {\"class\": \"public-key-only zero-signing-query fresh-message forgery\", \"public_forger_secret_inputs\": 0, \"signing_queries\": 0},\n"
             "  \"parameters\": {\"m\": %u, \"n\": %u, \"q\": %u, \"B\": %u, \"omega\": %u, \"K\": %u, \"L\": %u, \"D\": %u},\n"
             "  \"randomness\": {\"key_generation\": \"upstream GLYPH RAND_bytes path\", \"messages\": \"OpenSSL RAND_bytes\", \"fresh_public_keys\": true, \"fresh_messages\": true},\n"
             "  \"trials\": {\"requested\": %u, \"completed\": %u, \"forgeries_accepted\": %u, \"unique_public_keys\": %u, \"unique_messages\": %u, \"unique_signatures\": %u},\n"
             "  \"controls\": {\"per_trial\": %u, \"total\": %u, \"rejected\": %u, \"changed_message\": %u, \"truncated_message\": %u, \"extended_message\": %u, \"changed_challenge_sign\": %u, \"changed_challenge_position\": %u, \"changed_floor\": %u, \"out_of_range_z1\": %u, \"out_of_range_z2\": %u},\n"
             "  \"forgery_coefficients\": {\"zero_floor\": %" PRIu64 ", \"z2_zero\": %" PRIu64 ", \"z2_negative\": %" PRIu64 ", \"z2_positive\": %" PRIu64 "},\n"
             "  \"selector_exhaustion\": {\"residues_tested\": %u, \"selector_failures\": %u, \"zero_branch\": %u, \"negative_branch\": %u, \"positive_branch\": %u, \"strict_floor_control_unreachable\": %u, \"floor_control_failures\": %u},\n"
             "  \"checks\": {\"all_forgeries_accepted\": %s, \"all_negative_controls_rejected\": %s, \"all_selector_residues_passed\": %s, \"strict_interior_responses\": %s, \"ordinary_upstream_glp_verify\": true, \"public_only_forge_api\": true, \"secret_keys_retained\": false, \"zero_signing_queries\": true},\n"
             "  \"resources\": {\"runtime_seconds\": %.9f, \"peak_rss_kib\": %ld, \"workers\": 1},\n"
             "  \"environment\": {\"compiler\": \"%s\", \"openssl\": \"%s\", \"endianness\": \"little\"}\n"
             "}\n",
             passed ? "PASS" : "FAIL", mode, GLYPH_PARAM_M, N, Q, B,
             OMEGA, GLYPH_PARAM_K, GLYPH_PARAM_L, GLYPH_PARAM_D,
             requested_trials, counts->completed_trials, counts->forge_accepts,
             counts->completed_trials, counts->completed_trials,
             counts->completed_trials, CONTROL_COUNT,
             requested_trials * CONTROL_COUNT, total_control_rejects,
             counts->control_rejects[CONTROL_CHANGED_MESSAGE],
             counts->control_rejects[CONTROL_TRUNCATED_MESSAGE],
             counts->control_rejects[CONTROL_EXTENDED_MESSAGE],
             counts->control_rejects[CONTROL_CHANGED_CHALLENGE_SIGN],
             counts->control_rejects[CONTROL_CHANGED_CHALLENGE_POSITION],
             counts->control_rejects[CONTROL_CHANGED_FLOOR],
             counts->control_rejects[CONTROL_Z1_BOUND],
             counts->control_rejects[CONTROL_Z2_BOUND],
             counts->zero_floor_coefficients, counts->z2_zero,
             counts->z2_negative, counts->z2_positive,
             selector->residues_tested, selector->selector_failures,
             selector->zero_branch, selector->negative_branch,
             selector->positive_branch,
             selector->strict_floor_control_unreachable,
             selector->floor_control_failures,
             counts->forge_accepts == requested_trials ? "true" : "false",
             total_control_rejects == requested_trials * CONTROL_COUNT
                 ? "true" : "false",
             selector->residues_tested == Q && selector->selector_failures == 0
                 ? "true" : "false",
             counts->zero_floor_coefficients ==
                     (uint64_t)requested_trials * (uint64_t)N
                 ? "true" : "false",
             runtime_seconds, peak_rss_kib, __VERSION__,
             OpenSSL_version(OPENSSL_VERSION));
    if (fclose(file) != 0) {
        ok = 0;
    }
    return ok > 0;
}

int main(int argc, char **argv) {
    const char *mode = NULL;
    const char *summary_path = NULL;
    const char *csv_path = NULL;
    uint32_t requested_trials = 0;
    struct glyph_selector_report selector;
    struct counters counts;
    unsigned char *message_digests = NULL;
    unsigned char *key_digests = NULL;
    unsigned char *signature_digests = NULL;
    FILE *csv = NULL;
    double started = -1.0;
    double finished = -1.0;
    double runtime_seconds = -1.0;
    struct rusage usage_record;
    long peak_rss_kib = -1;
    int fatal_error = 0;
    int passed;
    uint32_t trial;
    int arg;

    for (arg = 1; arg < argc; ++arg) {
        if (strcmp(argv[arg], "--mode") == 0 && arg + 1 < argc) {
            mode = argv[++arg];
        } else if (strcmp(argv[arg], "--trials") == 0 && arg + 1 < argc) {
            if (!parse_u32(argv[++arg], &requested_trials)) {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[arg], "--summary") == 0 && arg + 1 < argc) {
            summary_path = argv[++arg];
        } else if (strcmp(argv[arg], "--trials-csv") == 0 && arg + 1 < argc) {
            csv_path = argv[++arg];
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (mode == NULL ||
        (strcmp(mode, "quick") != 0 && strcmp(mode, "full") != 0) ||
        requested_trials == 0 || summary_path == NULL || csv_path == NULL) {
        usage(argv[0]);
        return 2;
    }
    if (!host_is_little_endian()) {
        fprintf(stderr,
                "The pinned 2018 implementation is reproduced only on "
                "little-endian hosts.\n");
        return 2;
    }
    if (RAND_status() != 1) {
        fprintf(stderr, "OpenSSL CSPRNG is not ready\n");
        return 2;
    }

    memset(&counts, 0, sizeof(counts));
    selector = glyph_exhaustive_selector_check();
    printf("Selector exhaustion: tested=%u/%u failures=%u branches=(%u,%u,%u)\n",
           selector.residues_tested, Q, selector.selector_failures,
           selector.zero_branch, selector.negative_branch,
           selector.positive_branch);
    if (selector.residues_tested != Q || selector.selector_failures != 0 ||
        selector.floor_control_failures != 0 ||
        selector.strict_floor_control_unreachable != 3u) {
        fprintf(stderr, "Exhaustive selector/control proof failed\n");
        return 1;
    }

    message_digests = calloc((size_t)requested_trials, 32u);
    key_digests = calloc((size_t)requested_trials, 32u);
    signature_digests = calloc((size_t)requested_trials, 32u);
    if (message_digests == NULL || key_digests == NULL ||
        signature_digests == NULL) {
        fprintf(stderr, "Unable to allocate uniqueness tables\n");
        fatal_error = 1;
        goto finish;
    }

    csv = fopen(csv_path, "wb");
    if (csv == NULL) {
        perror(csv_path);
        fatal_error = 1;
        goto finish;
    }
    if (fprintf(csv,
                "trial,message_sha256,public_key_sha256,signature_sha256,"
                "forge_accept,changed_message_reject,truncated_message_reject,"
                "extended_message_reject,changed_challenge_sign_reject,"
                "changed_challenge_position_reject,changed_floor_reject,"
                "out_of_range_z1_reject,out_of_range_z2_reject,"
                "zero_floor_coefficients,z2_zero,z2_negative,z2_positive,"
                "floor_control_index,floor_control_value,signing_queries\n") < 0) {
        fatal_error = 1;
        goto finish;
    }

    started = monotonic_seconds();
    if (started < 0.0) {
        perror("clock_gettime");
        fatal_error = 1;
        goto finish;
    }

    for (trial = 0; trial < requested_trials; ++trial) {
        glp_signing_key_t secret_key;
        glp_public_key_t public_key;
        glp_signature_t forgery;
        glp_signature_t control;
        struct glyph_forge_stats forge_stats;
        unsigned char message[MESSAGE_BYTES];
        unsigned char changed_message[MESSAGE_BYTES + 1u];
        unsigned char public_key_bytes[2 * N];
        unsigned char signature_bytes[4 * N + 4 * OMEGA];
        unsigned char message_hash[32];
        unsigned char public_key_hash[32];
        unsigned char signature_hash[32];
        char message_hex[65];
        char public_key_hex[65];
        char signature_hex[65];
        int controls[CONTROL_COUNT] = {0};
        int replacement_position;
        uint32_t floor_control_index = 0;
        uint32_t floor_control_value = 0;
        int forged;
        int forge_accept;
        unsigned int i;

        /* Setup is legitimate.  The secret is cleansed and never serialized. */
        glp_gen_sk(&secret_key);
        glp_gen_pk(&public_key, secret_key);
        OPENSSL_cleanse(&secret_key, sizeof(secret_key));

        /* The attacker chooses fresh OS-random message bytes after key setup. */
        if (RAND_bytes(message, (int)sizeof(message)) != 1) {
            fprintf(stderr, "RAND_bytes failed at trial %u\n", trial);
            fatal_error = 1;
            break;
        }
        forged = glyph_public_forge(&forgery, &public_key, message,
                                    sizeof(message), &forge_stats);
        forge_accept =
            forged && glp_verify(forgery, public_key, message,
                                 sizeof(message)) == 1;

        memcpy(changed_message, message, sizeof(message));
        changed_message[0] ^= 0x80u;
        controls[CONTROL_CHANGED_MESSAGE] =
            forged && glp_verify(forgery, public_key, changed_message,
                                 sizeof(message)) == 0;
        controls[CONTROL_TRUNCATED_MESSAGE] =
            forged && glp_verify(forgery, public_key, message,
                                 sizeof(message) - 1u) == 0;
        memcpy(changed_message, message, sizeof(message));
        changed_message[sizeof(message)] = 0xa5u;
        controls[CONTROL_EXTENDED_MESSAGE] =
            forged && glp_verify(forgery, public_key, changed_message,
                                 sizeof(changed_message)) == 0;

        control = forgery;
        control.c.sign[0] ^= 1u;
        controls[CONTROL_CHANGED_CHALLENGE_SIGN] =
            forged && glp_verify(control, public_key, message,
                                 sizeof(message)) == 0;

        control = forgery;
        replacement_position = unused_challenge_position(&control.c);
        if (replacement_position < 0) {
            fprintf(stderr, "No unused challenge position at trial %u\n", trial);
            fatal_error = 1;
            break;
        }
        control.c.pos[0] = (uint16_t)replacement_position;
        controls[CONTROL_CHANGED_CHALLENGE_POSITION] =
            forged && glp_verify(control, public_key, message,
                                 sizeof(message)) == 0;

        controls[CONTROL_CHANGED_FLOOR] =
            forged &&
            glyph_build_floor_control(&control, &forgery, &public_key,
                                      &floor_control_index,
                                      &floor_control_value) &&
            floor_control_value != 0 &&
            glyph_centered_abs(control.z2[floor_control_index]) <
                GLYPH_PARAM_K &&
            glp_verify(control, public_key, message, sizeof(message)) == 0;

        control = forgery;
        control.z1[0] = (RINGELT)(GLYPH_PARAM_K + 1u);
        controls[CONTROL_Z1_BOUND] =
            forged &&
            glyph_centered_abs(control.z1[0]) == GLYPH_PARAM_K + 1u &&
            glp_verify(control, public_key, message, sizeof(message)) == 0;

        control = forgery;
        control.z2[0] = (RINGELT)(GLYPH_PARAM_K + 1u);
        controls[CONTROL_Z2_BOUND] =
            forged &&
            glyph_centered_abs(control.z2[0]) == GLYPH_PARAM_K + 1u &&
            glp_verify(control, public_key, message, sizeof(message)) == 0;

        if (!sha256_bytes(message, sizeof(message), message_hash) ||
            !canonical_public_key(&public_key, public_key_bytes) ||
            !sha256_bytes(public_key_bytes, sizeof(public_key_bytes),
                          public_key_hash) ||
            !canonical_signature(&forgery, signature_bytes) ||
            !sha256_bytes(signature_bytes, sizeof(signature_bytes),
                          signature_hash)) {
            fprintf(stderr, "Canonical hashing failed at trial %u\n", trial);
            fatal_error = 1;
            break;
        }
        if (digest_seen(message_digests, trial, message_hash) ||
            digest_seen(key_digests, trial, public_key_hash) ||
            digest_seen(signature_digests, trial, signature_hash)) {
            fprintf(stderr, "Freshness/uniqueness collision at trial %u\n", trial);
            fatal_error = 1;
            break;
        }
        memcpy(message_digests + 32u * trial, message_hash, 32u);
        memcpy(key_digests + 32u * trial, public_key_hash, 32u);
        memcpy(signature_digests + 32u * trial, signature_hash, 32u);
        hex_encode(message_hash, sizeof(message_hash), message_hex);
        hex_encode(public_key_hash, sizeof(public_key_hash), public_key_hex);
        hex_encode(signature_hash, sizeof(signature_hash), signature_hex);

        if (fprintf(csv,
                    "%u,%s,%s,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%u,%u,%u,"
                    "%u,%u,%u,0\n",
                    trial, message_hex, public_key_hex, signature_hex,
                    forge_accept,
                    controls[CONTROL_CHANGED_MESSAGE],
                    controls[CONTROL_TRUNCATED_MESSAGE],
                    controls[CONTROL_EXTENDED_MESSAGE],
                    controls[CONTROL_CHANGED_CHALLENGE_SIGN],
                    controls[CONTROL_CHANGED_CHALLENGE_POSITION],
                    controls[CONTROL_CHANGED_FLOOR],
                    controls[CONTROL_Z1_BOUND],
                    controls[CONTROL_Z2_BOUND],
                    forge_stats.zero_floor_coefficients,
                    forge_stats.z2_zero, forge_stats.z2_negative,
                    forge_stats.z2_positive, floor_control_index,
                    floor_control_value) < 0) {
            fprintf(stderr, "CSV write failed at trial %u\n", trial);
            fatal_error = 1;
            break;
        }

        ++counts.completed_trials;
        counts.forge_accepts += (uint32_t)forge_accept;
        for (i = 0; i < CONTROL_COUNT; ++i) {
            counts.control_rejects[i] += (uint32_t)controls[i];
        }
        counts.zero_floor_coefficients +=
            forge_stats.zero_floor_coefficients;
        counts.z2_zero += forge_stats.z2_zero;
        counts.z2_negative += forge_stats.z2_negative;
        counts.z2_positive += forge_stats.z2_positive;

        printf("trial=%u forge=%s controls=%u/%u REJECTED floor-zero=%u "
               "z2=(%u,%u,%u)\n",
               trial, forge_accept ? "ACCEPT" : "REJECT",
               (unsigned int)(controls[0] + controls[1] + controls[2] +
                              controls[3] + controls[4] + controls[5] +
                              controls[6] + controls[7]),
               CONTROL_COUNT, forge_stats.zero_floor_coefficients,
               forge_stats.z2_zero, forge_stats.z2_negative,
               forge_stats.z2_positive);

        if (!forge_accept) {
            fprintf(stderr, "Forgery rejected at trial %u\n", trial);
            fatal_error = 1;
            break;
        }
        for (i = 0; i < CONTROL_COUNT; ++i) {
            if (!controls[i]) {
                fprintf(stderr, "Control %s failed at trial %u\n",
                        CONTROL_NAMES[i], trial);
                fatal_error = 1;
                break;
            }
        }
        if (fatal_error) {
            break;
        }
    }

    finished = monotonic_seconds();
    runtime_seconds = finished >= started ? finished - started : -1.0;
    if (getrusage(RUSAGE_SELF, &usage_record) == 0) {
        peak_rss_kib = usage_record.ru_maxrss;
    }

finish:
    if (csv != NULL && fclose(csv) != 0) {
        perror(csv_path);
        fatal_error = 1;
    }
    OPENSSL_clear_free(message_digests,
                       (size_t)requested_trials * 32u);
    OPENSSL_clear_free(key_digests,
                       (size_t)requested_trials * 32u);
    OPENSSL_clear_free(signature_digests,
                       (size_t)requested_trials * 32u);

    if (started <= 0.0) {
        runtime_seconds = -1.0;
    }
    passed = !fatal_error && counts.completed_trials == requested_trials &&
             counts.forge_accepts == requested_trials &&
             counts.zero_floor_coefficients ==
                 (uint64_t)requested_trials * (uint64_t)N;
    if (passed) {
        unsigned int i;
        for (i = 0; i < CONTROL_COUNT; ++i) {
            if (counts.control_rejects[i] != requested_trials) {
                passed = 0;
            }
        }
    }
    if (!write_summary(summary_path, mode, requested_trials, &counts,
                       &selector, runtime_seconds, peak_rss_kib, passed)) {
        fprintf(stderr, "Unable to write summary\n");
        passed = 0;
    }

    printf("========================================\n");
    printf("ATTACK REPRODUCTION: %s\n\n", passed ? "PASS" : "FAIL");
    printf("Scheme: GLYPH (m=%u, n=%u, q=%u, B=%u, omega=%u)\n",
           GLYPH_PARAM_M, N, Q, B, OMEGA);
    printf("Result: public-key-only, zero-query fresh-message forgery\n");
    printf("Fresh-message forgeries: %u/%u ACCEPTED\n",
           counts.forge_accepts, requested_trials);
    printf("Negative controls: %u/%u REJECTED\n",
           counts.completed_trials * CONTROL_COUNT,
           requested_trials * CONTROL_COUNT);
    printf("Signing queries: 0\n");
    printf("Secret inputs to public forger: 0\n");
    printf("Ordinary pinned glp_verify: ACCEPTED\n");
    printf("Residues exhaustively checked: %u/%u\n",
           selector.residues_tested, Q);
    printf("Runtime: %.9f seconds\n", runtime_seconds);
    printf("Peak RAM: %ld KiB\n", peak_rss_kib);
    printf("Workers: 1\n");
    printf("Compiler: %s\n", __VERSION__);
    printf("OpenSSL: %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("========================================\n");
    return passed ? 0 : 1;
}
