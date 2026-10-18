use ark_bn254::{Bn254, Fq, Fr, G1Affine, G1Projective, G2Projective};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup, Group,
};
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::time::Instant;

type GT = PairingOutput<Bn254>;

const H0_DOMAIN: &[u8] = b"FABS-2026-022/H0/ARK-BN254/v1\0";
const H1_DOMAIN: &[u8] = b"FABS-2026-022/H1/ARK-BN254/v1\0";
const SCALAR_DOMAIN: &[u8] = b"FABS-INDEPENDENT/SCALAR/v1\0";
const ALPHAS: [u64; 5] = [1, 2, 3, 5, 7];

#[derive(Clone)]
struct PublicParameters {
    x: GT,
}

#[derive(Clone)]
struct SecretKey {
    sk1: G2Projective,
    sk2: Vec<G1Projective>,
}

#[derive(Clone)]
struct Signature {
    a: G1Projective,
    b: G1Projective,
    c_point: G2Projective,
    challenge: Fr,
    s_alpha: Fr,
    s_k: Fr,
    s_i: Vec<Fr>,
}

struct AttackArtifact {
    signature: Signature,
    y: GT,
    z: GT,
    w: G1Projective,
    adversary_h0_queries: usize,
    adversary_h1_queries: usize,
}

#[derive(Default)]
struct OracleStats {
    honest_h0_queries: usize,
    honest_h1_queries: usize,
    verifier_h0_queries: usize,
    verifier_h1_queries: usize,
}

fn g1() -> G1Projective {
    G1Projective::generator()
}

fn g2() -> G2Projective {
    G2Projective::generator()
}

fn pair(p: &G1Projective, q: &G2Projective) -> GT {
    Bn254::pairing(p.clone().into_affine(), q.clone().into_affine())
}

fn canonical<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    value.serialize_compressed(&mut out).expect("canonical serialization");
    out
}

fn append_typed(out: &mut Vec<u8>, tag: u8, payload: &[u8]) {
    out.push(tag);
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    out.extend_from_slice(payload);
}

fn h0(
    a: &G1Projective,
    b: &G1Projective,
    c_point: &G2Projective,
    y: &GT,
    z: &GT,
    w: &G1Projective,
    message: &[u8],
) -> Fr {
    let mut input = Vec::new();
    input.extend_from_slice(H0_DOMAIN);
    input.extend_from_slice(&7u32.to_be_bytes());
    append_typed(&mut input, 0x01, &canonical(&a.clone().into_affine()));
    append_typed(&mut input, 0x02, &canonical(&b.clone().into_affine()));
    append_typed(&mut input, 0x03, &canonical(&c_point.clone().into_affine()));
    append_typed(&mut input, 0x04, &canonical(y));
    append_typed(&mut input, 0x05, &canonical(z));
    append_typed(&mut input, 0x06, &canonical(&w.clone().into_affine()));
    append_typed(&mut input, 0x07, message);
    Fr::from_be_bytes_mod_order(&Sha256::digest(&input))
}

fn h1(attribute: &[u8]) -> G1Projective {
    for counter in 0u32.. {
        let mut hasher = Sha256::new();
        hasher.update(H1_DOMAIN);
        hasher.update((attribute.len() as u64).to_be_bytes());
        hasher.update(attribute);
        hasher.update(counter.to_be_bytes());
        let digest = hasher.finalize();
        let x = Fq::from_be_bytes_mod_order(&digest);
        let rhs = x.square() * x + Fq::from(3u64);
        if let Some(mut y) = rhs.sqrt() {
            let wanted_odd = (digest[0] & 1) == 1;
            if y.into_bigint().is_odd() != wanted_odd {
                y = -y;
            }
            let affine = G1Affine::new_unchecked(x, y);
            assert!(affine.is_on_curve());
            assert!(affine.is_in_correct_subgroup_assuming_on_curve());
            let point = affine.into_group();
            assert!(!point.is_zero());
            return point;
        }
    }
    unreachable!()
}

fn derive_fr(label: &[u8], trial: u64, index: u64, nonzero: bool) -> Fr {
    for counter in 0u32.. {
        let mut hasher = Sha256::new();
        hasher.update(SCALAR_DOMAIN);
        hasher.update((label.len() as u64).to_be_bytes());
        hasher.update(label);
        hasher.update(trial.to_be_bytes());
        hasher.update(index.to_be_bytes());
        hasher.update(counter.to_be_bytes());
        let value = Fr::from_be_bytes_mod_order(&hasher.finalize());
        if !nonzero || !value.is_zero() {
            return value;
        }
    }
    unreachable!()
}

fn setup(alpha: Fr) -> PublicParameters {
    assert!(!alpha.is_zero());
    PublicParameters { x: pair(&g1(), &g2()) * alpha }
}

fn attributes(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| format!("FABS-ATTRIBUTE-{i:03}").into_bytes())
        .collect()
}

// All-AND MSP with reconstruction coefficients gamma_i=1:
// (1,1,0,...), (0,-1,1,...), ..., (0,...,-1).
fn all_and_share(alpha_plus_r: Fr, v: &[Fr], row: usize, n: usize) -> Fr {
    if n == 1 {
        assert!(v.is_empty());
        return alpha_plus_r;
    }
    if row == 0 {
        alpha_plus_r + v[0]
    } else if row + 1 == n {
        -v[n - 2]
    } else {
        -v[row - 1] + v[row]
    }
}

fn keygen_all_and(
    alpha: Fr,
    attrs: &[Vec<u8>],
    trial: u64,
    stats: &mut OracleStats,
) -> SecretKey {
    let n = attrs.len();
    let r = derive_fr(b"honest-key-r", trial, n as u64, true);
    let v: Vec<Fr> = (0..n.saturating_sub(1))
        .map(|i| derive_fr(b"honest-key-v", trial, ((n as u64) << 32) | i as u64, false))
        .collect();
    let sk1 = g2() * r;
    let mut sk2 = Vec::with_capacity(n);
    for (i, attr) in attrs.iter().enumerate() {
        let share = all_and_share(alpha + r, &v, i, n);
        stats.honest_h1_queries += 1;
        sk2.push(g1() * share + h1(attr) * r);
    }
    SecretKey { sk1, sk2 }
}

fn honest_sign(
    pp: &PublicParameters,
    sk: &SecretKey,
    attrs: &[Vec<u8>],
    message: &[u8],
    trial: u64,
    stats: &mut OracleStats,
) -> Signature {
    let n = attrs.len();
    let k = derive_fr(b"honest-k", trial, n as u64, true);
    let t = derive_fr(b"honest-t", trial, n as u64, true);
    let r_alpha = derive_fr(b"honest-r-alpha", trial, n as u64, false);
    let r_k = derive_fr(b"honest-r-k", trial, n as u64, false);
    let r_i: Vec<Fr> = (0..n)
        .map(|i| derive_fr(b"honest-r-i", trial, ((n as u64) << 32) | i as u64, false))
        .collect();
    let kt = k * t;
    let mut a = G1Projective::zero();
    for component in &sk.sk2 {
        a += component.clone() * kt;
    }
    let mut b = g1() * k;
    for attr in attrs {
        stats.honest_h1_queries += 1;
        b += h1(attr) * k;
    }
    let c_point = sk.sk1 * t;
    let y = pp.x * kt;
    let z = pp.x * r_alpha;
    let mut w = g1() * r_k;
    for (attr, nonce) in attrs.iter().zip(&r_i) {
        stats.honest_h1_queries += 1;
        w += h1(attr) * nonce;
    }
    stats.honest_h0_queries += 1;
    let challenge = h0(&a, &b, &c_point, &y, &z, &w, message);
    let s_alpha = r_alpha - kt * challenge;
    let s_k = r_k - k * challenge;
    let s_i = r_i.into_iter().map(|r| r - k * challenge).collect();
    Signature { a, b, c_point, challenge, s_alpha, s_k, s_i }
}

fn verify(
    pp: &PublicParameters,
    signature: &Signature,
    attrs: &[Vec<u8>],
    message: &[u8],
    stats: &mut OracleStats,
) -> bool {
    if signature.s_i.len() != attrs.len() {
        return false;
    }
    let y = pair(&signature.a, &g2()) - pair(&signature.b, &signature.c_point);
    let z = pp.x * signature.s_alpha + y * signature.challenge;
    let mut w = g1() * signature.s_k;
    for (attr, response) in attrs.iter().zip(&signature.s_i) {
        stats.verifier_h1_queries += 1;
        w += h1(attr) * response;
    }
    w += signature.b * signature.challenge;
    stats.verifier_h0_queries += 1;
    let challenge_prime = h0(
        &signature.a,
        &signature.b,
        &signature.c_point,
        &y,
        &z,
        &w,
        message,
    );
    challenge_prime == signature.challenge
}

fn forge_minimal(pp: &PublicParameters, attrs: &[Vec<u8>], message: &[u8], trial: u64) -> AttackArtifact {
    let a = g1();
    let b = g1();
    let c_point = g2();
    let y = pair(&a, &g2()) - pair(&b, &c_point);
    assert!(y.is_zero());
    let z = pp.x;
    let r_k = derive_fr(b"minimal-r-k", trial, attrs.len() as u64, true);
    let w = g1() * r_k;
    let challenge = h0(&a, &b, &c_point, &y, &z, &w, message);
    let signature = Signature {
        a,
        b,
        c_point,
        challenge,
        s_alpha: Fr::one(),
        s_k: r_k - challenge,
        s_i: vec![Fr::zero(); attrs.len()],
    };
    AttackArtifact {
        signature,
        y,
        z,
        w,
        adversary_h0_queries: 1,
        adversary_h1_queries: 0,
    }
}

fn forge_strong(pp: &PublicParameters, attrs: &[Vec<u8>], message: &[u8], trial: u64) -> AttackArtifact {
    let a = g1();
    let b = g1();
    let c_point = g2();
    let y = pair(&a, &g2()) - pair(&b, &c_point);
    assert!(y.is_zero());
    let z = pp.x;
    let r_k = derive_fr(b"strong-r-k", trial, attrs.len() as u64, true);
    let r_i: Vec<Fr> = (0..attrs.len())
        .map(|i| derive_fr(b"strong-r-i", trial, i as u64, true))
        .collect();
    let mut w = g1() * r_k;
    for (attr, nonce) in attrs.iter().zip(&r_i) {
        w += h1(attr) * nonce;
    }
    assert!(!w.is_zero());
    let challenge = h0(&a, &b, &c_point, &y, &z, &w, message);
    let signature = Signature {
        a,
        b,
        c_point,
        challenge,
        s_alpha: Fr::one(),
        s_k: r_k - challenge,
        s_i: r_i,
    };
    AttackArtifact {
        signature,
        y,
        z,
        w,
        adversary_h0_queries: 1,
        adversary_h1_queries: attrs.len(),
    }
}

fn signature_hash(signature: &Signature) -> String {
    let mut bytes = Vec::new();
    append_typed(&mut bytes, 1, &canonical(&signature.a.clone().into_affine()));
    append_typed(&mut bytes, 2, &canonical(&signature.b.clone().into_affine()));
    append_typed(&mut bytes, 3, &canonical(&signature.c_point.clone().into_affine()));
    append_typed(&mut bytes, 4, &canonical(&signature.challenge));
    append_typed(&mut bytes, 5, &canonical(&signature.s_alpha));
    append_typed(&mut bytes, 6, &canonical(&signature.s_k));
    for response in &signature.s_i {
        append_typed(&mut bytes, 7, &canonical(response));
    }
    hex(&Sha256::digest(&bytes))
}

fn point_hash<T: CanonicalSerialize>(value: &T) -> String {
    hex(&Sha256::digest(canonical(value)))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn proc_threads() -> usize {
    let status = fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
    status
        .lines()
        .find_map(|line| line.strip_prefix("Threads:").map(str::trim))
        .expect("Threads field")
        .parse()
        .expect("thread count")
}

fn negative_controls(
    pp: &PublicParameters,
    base: &Signature,
    attrs: &[Vec<u8>],
    message: &[u8],
    stats: &mut OracleStats,
) -> Vec<(&'static str, bool)> {
    let mut results = Vec::new();
    results.push(("held_message_change", !verify(pp, base, attrs, b"changed-held-message", stats)));

    let mut changed = base.clone();
    changed.challenge += Fr::one();
    results.push(("challenge_change", !verify(pp, &changed, attrs, message, stats)));

    let mut changed = base.clone();
    changed.a += g1();
    results.push(("A_change", !verify(pp, &changed, attrs, message, stats)));

    let mut changed = base.clone();
    changed.b += g1();
    results.push(("B_change", !verify(pp, &changed, attrs, message, stats)));

    let mut changed = base.clone();
    changed.c_point += g2();
    results.push(("C_change", !verify(pp, &changed, attrs, message, stats)));

    let mut changed = base.clone();
    changed.s_alpha += Fr::one();
    results.push(("s_alpha_change", !verify(pp, &changed, attrs, message, stats)));

    let mut changed = base.clone();
    changed.s_k += Fr::one();
    results.push(("s_k_change", !verify(pp, &changed, attrs, message, stats)));

    let mut changed = base.clone();
    changed.s_i[37] += Fr::one();
    results.push(("one_s_i_change", !verify(pp, &changed, attrs, message, stats)));
    results
}

fn main() {
    let run_start = Instant::now();
    let threads_start = proc_threads();
    assert_eq!(threads_start, 1, "program must create exactly one thread");
    assert_eq!(std::env::var("CARGO_BUILD_JOBS").as_deref(), Ok("1"));

    let attrs100 = attributes(100);
    let unique: HashSet<&[u8]> = attrs100.iter().map(Vec::as_slice).collect();
    assert_eq!(unique.len(), 100);
    let h1_anchor = h1(&attrs100[0]).into_affine();

    println!("{{\"event\":\"configuration\",\"curve\":\"ark-bn254-0.4.0\",\"pairing\":\"actual_arkworks_Bn254\",\"h0\":\"typed_canonical_sha256_v1\",\"h1\":\"try_and_increment_sha256_to_bn254_g1_v1\",\"program_threads\":{threads_start},\"cargo_build_jobs\":1,\"trials\":5,\"attributes\":100,\"h1_anchor_sha256\":\"{}\"}}", point_hash(&h1_anchor));

    let mut successes = 0usize;
    let mut aggregate_attack_ns = 0u128;
    for (trial_index, alpha_u64) in ALPHAS.iter().copied().enumerate() {
        let trial = trial_index as u64;
        let alpha = Fr::from(alpha_u64);
        let pp = setup(alpha);
        let mut stats = OracleStats::default();
        let mut honest_ok = true;
        let mut honest_hashes = Vec::new();
        let mut honest_messages = Vec::new();
        for n in [1usize, 3, 100] {
            let attrs = attributes(n);
            let message = format!("honest-control/alpha-{alpha_u64}/attrs-{n}").into_bytes();
            honest_messages.push(message.clone());
            let sk = keygen_all_and(alpha, &attrs, trial, &mut stats);
            let sig = honest_sign(&pp, &sk, &attrs, &message, trial, &mut stats);
            let accepted = verify(&pp, &sig, &attrs, &message, &mut stats);
            honest_ok &= accepted;
            honest_hashes.push(format!("{n}:{}", signature_hash(&sig)));
        }

        let minimal_message = format!("attacker-chosen/minimal/fresh/alpha-{alpha_u64}").into_bytes();
        let strong_message = format!("attacker-chosen/strong/fresh/alpha-{alpha_u64}").into_bytes();
        let never_signed = honest_messages.iter().all(|m| m != &minimal_message && m != &strong_message);
        let attack_start = Instant::now();
        let minimal = forge_minimal(&pp, &attrs100, &minimal_message, trial);
        let minimal_ok = verify(&pp, &minimal.signature, &attrs100, &minimal_message, &mut stats);
        let strong = forge_strong(&pp, &attrs100, &strong_message, trial);
        let strong_ok = verify(&pp, &strong.signature, &attrs100, &strong_message, &mut stats);
        let controls = negative_controls(&pp, &strong.signature, &attrs100, &strong_message, &mut stats);
        let attack_ns = attack_start.elapsed().as_nanos();
        aggregate_attack_ns += attack_ns;

        let strong_nonidentity = !strong.signature.a.is_zero()
            && !strong.signature.b.is_zero()
            && !strong.signature.c_point.is_zero()
            && !strong.z.is_zero()
            && !strong.w.is_zero();
        let all_nonzero_s_i = strong.signature.s_i.iter().all(|s| !s.is_zero());
        let controls_ok = controls.iter().all(|(_, rejected)| *rejected);
        let query_game_ok = minimal.adversary_h0_queries == 1
            && minimal.adversary_h1_queries == 0
            && strong.adversary_h0_queries == 1
            && strong.adversary_h1_queries == 100
            && never_signed;
        let y_identity = minimal.y.is_zero() && strong.y.is_zero();
        let trial_ok = honest_ok
            && minimal_ok
            && strong_ok
            && strong_nonidentity
            && all_nonzero_s_i
            && controls_ok
            && query_game_ok
            && y_identity;
        if trial_ok {
            successes += 1;
        }
        let controls_json = controls
            .iter()
            .map(|(name, rejected)| format!("\"{name}\":{rejected}"))
            .collect::<Vec<_>>()
            .join(",");
        println!("{{\"event\":\"trial\",\"trial\":{},\"alpha_u64\":{},\"honest_1_3_100_accept\":{},\"minimal_accept\":{},\"strong_accept\":{},\"minimal_adversary_h0\":{},\"minimal_adversary_h1\":{},\"strong_adversary_h0\":{},\"strong_adversary_h1\":{},\"key_queries\":0,\"signing_queries\":0,\"never_signed_message\":{},\"strong_A_B_C_Z_W_nonidentity\":{},\"strong_all_s_i_nonzero\":{},\"Y_identity\":{},\"negative_controls\":{{{}}},\"minimal_signature_sha256\":\"{}\",\"strong_signature_sha256\":\"{}\",\"public_X_sha256\":\"{}\",\"honest_signature_hashes\":\"{}\",\"attack_wall_ns\":{},\"trial_pass\":{}}}",
            trial_index + 1,
            alpha_u64,
            honest_ok,
            minimal_ok,
            strong_ok,
            minimal.adversary_h0_queries,
            minimal.adversary_h1_queries,
            strong.adversary_h0_queries,
            strong.adversary_h1_queries,
            never_signed,
            strong_nonidentity,
            all_nonzero_s_i,
            y_identity,
            controls_json,
            signature_hash(&minimal.signature),
            signature_hash(&strong.signature),
            point_hash(&pp.x),
            honest_hashes.join(";"),
            attack_ns,
            trial_ok);
    }

    let threads_end = proc_threads();
    let pass = successes == ALPHAS.len() && threads_start == 1 && threads_end == 1;
    println!("{{\"event\":\"summary\",\"trials\":{},\"successes\":{},\"full_100_attribute_acceptance\":{},\"fresh_message\":{},\"key_queries\":0,\"signing_queries\":0,\"program_threads_start\":{},\"program_threads_end\":{},\"aggregate_attack_wall_ns\":{},\"total_program_wall_ns\":{},\"verdict\":\"{}\"}}",
        ALPHAS.len(), successes, pass, pass, threads_start, threads_end,
        aggregate_attack_ns, run_start.elapsed().as_nanos(), if pass { "PASS" } else { "FAIL" });
    println!("========================================");
    println!("ATTACK REPRODUCTION: {}", if pass { "PASS" } else { "FAIL" });
    println!("Scheme: FABS KP-ABS, ePrint 2026/022, Figure 1");
    println!("Result: public-key-only fresh-message forgery");
    println!("Fresh-message forgery: {}", if pass { "ACCEPTED" } else { "FAILED" });
    println!("Negative controls: {}", if pass { "ALL REJECTED" } else { "FAILED" });
    println!("Trials: {}/{}", successes, ALPHAS.len());
    println!("========================================");
    if !pass {
        std::process::exit(1);
    }
}
