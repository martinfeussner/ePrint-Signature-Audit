use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use bls_aiso_as::bls::{verify, BLSKeyPair};
use bls_aiso_as::common::hash_to_g2;
use std::panic::{catch_unwind, AssertUnwindSafe};

const FRESH_MESSAGE: &str = "Definition 33 fresh-message forgery / ePrint 2026-1394";
const CHANGED_MESSAGE: &str = "Definition 33 changed-message control / ePrint 2026-1394";

fn artifact_accepts(vk: &G1Affine, message: &str, signature: &G2Affine) -> bool {
    catch_unwind(AssertUnwindSafe(|| verify(vk, message, signature))).is_ok()
}

fn main() {
    // Keep expected rejection controls quiet: the artifact verifier signals
    // rejection by assertion failure, so the harness catches those panics.
    std::panic::set_hook(Box::new(|_| {}));

    // Definition 33 order: the challenger first generates and reveals vk_A.
    let honest_a = BLSKeyPair::new();
    let vk_a = honest_a.pk;

    // The corrupt E now chooses a known nonzero beta and its public key.  The
    // second value is only a deterministic guard against the negligible case
    // vk_A == 42*G1, which would make vk_E the identity.
    let beta_42 = Scalar::from(42u64);
    let beta_43 = Scalar::from(43u64);
    let beta_pk_42 = G1Affine::from(G1Affine::generator() * beta_42);
    let beta = if vk_a == beta_pk_42 { beta_43 } else { beta_42 };
    let beta_pk = G1Affine::from(G1Affine::generator() * beta);
    let vk_e = G1Affine::from(G1Projective::from(beta_pk) - G1Projective::from(vk_a));

    // This is the exact aggregation expression used by the author artifact's
    // test programs: direct BLS12-381 G1 point addition.
    let aggregate_vk =
        G1Affine::from(G1Projective::from(vk_a) + G1Projective::from(vk_e));

    assert_eq!(aggregate_vk, beta_pk, "KAg did not cancel vk_A");
    assert!(!bool::from(vk_a.is_identity()), "honest key is identity");
    assert!(!bool::from(vk_e.is_identity()), "rogue key is identity");
    assert!(!bool::from(aggregate_vk.is_identity()), "aggregate key is identity");
    assert!(bool::from(vk_a.is_torsion_free()), "honest key is not subgroup-clean");
    assert!(bool::from(vk_e.is_torsion_free()), "rogue key is not subgroup-clean");
    assert!(bool::from(aggregate_vk.is_torsion_free()), "aggregate key is not subgroup-clean");

    // No signing method or signing oracle is called anywhere in this program.
    let signing_queries = 0u64;
    let forged_signature = G2Affine::from(hash_to_g2(FRESH_MESSAGE) * beta);
    let changed_signature = G2Affine::from(
        G2Projective::from(forged_signature) + G2Projective::from(G2Affine::generator()),
    );

    let forged_accepts = artifact_accepts(&aggregate_vk, FRESH_MESSAGE, &forged_signature);
    let changed_message_accepts =
        artifact_accepts(&aggregate_vk, CHANGED_MESSAGE, &forged_signature);
    let changed_signature_accepts =
        artifact_accepts(&aggregate_vk, FRESH_MESSAGE, &changed_signature);
    let honest_key_substitution_accepts =
        artifact_accepts(&vk_a, FRESH_MESSAGE, &forged_signature);

    // The artifact exposes typed subgroup points, not a byte-decoding verifier
    // API. Check malformed encodings at the concrete curve boundary anyway.
    let invalid_g1_rejected = bool::from(G1Affine::from_compressed(&[0xff; 48]).is_none());
    let invalid_g2_rejected = bool::from(G2Affine::from_compressed(&[0xff; 96]).is_none());

    let pass = signing_queries == 0
        && forged_accepts
        && !changed_message_accepts
        && !changed_signature_accepts
        && !honest_key_substitution_accepts
        && invalid_g1_rejected
        && invalid_g2_rejected;

    println!("profile=BLS12-381_G1PK_G2SIG_SHA256_XMD_AUTHOR_ARTIFACT");
    println!("scope=DEFINITION_33_EXACT_VERIFIER_DIAGNOSTIC");
    println!("artifact_lifecycle_conformance=NO_CENTRAL_KEYGEN_BYPASSED");
    println!("honest_vk_a_generated_by_artifact_keygen=true");
    println!("rogue_vk_e_chosen_after_vk_a=true");
    println!("beta_nonzero=true");
    println!("vk_a_nonidentity=true");
    println!("vk_e_nonidentity=true");
    println!("aggregate_vk_nonidentity=true");
    println!("all_attack_keys_torsion_free=true");
    println!("kag_equals_beta_g1=true");
    println!("signing_queries={signing_queries}");
    println!("fresh_message_was_never_queried=true");
    println!("ordinary_artifact_verifier_forgery={}", if forged_accepts { "ACCEPT" } else { "REJECT" });
    println!("control_changed_message={}", if changed_message_accepts { "ACCEPT" } else { "REJECT" });
    println!("control_changed_signature={}", if changed_signature_accepts { "ACCEPT" } else { "REJECT" });
    println!("control_honest_key_substitution={}", if honest_key_substitution_accepts { "ACCEPT" } else { "REJECT" });
    println!("control_invalid_g1_encoding={}", if invalid_g1_rejected { "REJECT" } else { "ACCEPT" });
    println!("control_invalid_g2_encoding={}", if invalid_g2_rejected { "REJECT" } else { "ACCEPT" });
    println!("result={}", if pass { "PASS" } else { "FAIL" });

    if !pass {
        std::process::exit(1);
    }
}
