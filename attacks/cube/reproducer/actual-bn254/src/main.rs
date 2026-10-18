use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use sha3::{Digest, Keccak256};

#[derive(Clone)]
struct Proof {
    a_bar: G1Projective,
    b_bar: G1Projective,
    u: G1Projective,
    s: Fr,
    t: Fr,
    u_gamma: Fr,
}

#[derive(Clone)]
struct Instance {
    x_public: G2Projective,
    bases: Vec<G1Projective>,
    h_gamma: G1Projective,
    messages: Vec<Fr>,
    context: [u8; 32],
}

fn g1() -> G1Projective {
    G1Projective::generator()
}

fn g2() -> G2Projective {
    G2Projective::generator()
}

fn scalar(label: u64) -> Fr {
    Fr::from(label)
}

fn make_instance(message_count: usize, offset: u64, context_byte: u8) -> (Instance, Fr, Fr) {
    let signing_key = scalar(37 + offset);
    let hidden_message = scalar(71 + offset);
    let bases = (0..message_count)
        .map(|i| g1() * scalar(101 + offset + 17 * i as u64))
        .collect();
    let messages = (0..message_count)
        .map(|i| scalar(1009 + offset + 29 * i as u64))
        .collect();
    let h_gamma = g1() * scalar(809 + offset);
    let mut context = [0u8; 32];
    context[..10].copy_from_slice(b"LetsVerify");
    context[31] = context_byte;
    (
        Instance {
            x_public: g2() * signing_key,
            bases,
            h_gamma,
            messages,
            context,
        },
        signing_key,
        hidden_message,
    )
}

fn cj(instance: &Instance) -> G1Projective {
    let mut out = g1();
    for (base, message) in instance.bases.iter().zip(&instance.messages) {
        out += base.clone() * *message;
    }
    out
}

fn field_word(value: &Fr) -> [u8; 32] {
    let raw = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - raw.len()..].copy_from_slice(&raw);
    out
}

fn fq_word<T: PrimeField>(value: &T) -> [u8; 32] {
    let raw = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - raw.len()..].copy_from_slice(&raw);
    out
}

fn append_point(payload: &mut Vec<u8>, point: &G1Projective) {
    let affine = point.clone().into_affine();
    if affine.is_zero() {
        payload.extend_from_slice(&[0u8; 64]);
    } else {
        payload.extend_from_slice(&fq_word(&affine.x));
        payload.extend_from_slice(&fq_word(&affine.y));
    }
}

fn challenge(instance: &Instance, proof: &Proof) -> Fr {
    let mut payload = Vec::new();
    payload.extend_from_slice(&instance.context);
    for message in &instance.messages {
        payload.extend_from_slice(&field_word(message));
    }
    append_point(&mut payload, &proof.a_bar);
    append_point(&mut payload, &proof.b_bar);
    append_point(&mut payload, &proof.u);
    Fr::from_be_bytes_mod_order(&Keccak256::digest(&payload))
}

fn honest_proof(instance: &Instance, signing_key: Fr, hidden_message: Fr) -> Proof {
    let e = scalar(43);
    let denominator = signing_key + e;
    let signature_a = (cj(instance) + instance.h_gamma * hidden_message)
        * denominator.inverse().expect("nonzero signing denominator");
    let r = scalar(47);
    let alpha = scalar(53);
    let beta = scalar(59);
    let delta = scalar(61);
    let a_bar = signature_a * r;
    let b_bar = (cj(instance) + instance.h_gamma * hidden_message) * r - a_bar * e;
    let u = cj(instance) * alpha + a_bar * beta + instance.h_gamma * delta;
    let mut proof = Proof {
        a_bar,
        b_bar,
        u,
        s: Fr::zero(),
        t: Fr::zero(),
        u_gamma: Fr::zero(),
    };
    let c = challenge(instance, &proof);
    proof.s = alpha + r * c;
    proof.t = beta - e * c;
    proof.u_gamma = delta + r * hidden_message * c;
    proof
}

fn verify(instance: &Instance, proof: &Proof) -> bool {
    let pairing_left = Bn254::pairing(
        proof.a_bar.clone().into_affine(),
        instance.x_public.clone().into_affine(),
    );
    let pairing_right = Bn254::pairing(proof.b_bar.clone().into_affine(), g2().into_affine());
    if pairing_left != pairing_right {
        return false;
    }
    let c = challenge(instance, proof);
    let left = proof.u + proof.b_bar * c;
    let right = cj(instance) * proof.s
        + proof.a_bar * proof.t
        + instance.h_gamma * proof.u_gamma;
    left == right
}

fn zero_proof() -> Proof {
    Proof {
        a_bar: G1Projective::zero(),
        b_bar: G1Projective::zero(),
        u: G1Projective::zero(),
        s: Fr::zero(),
        t: Fr::zero(),
        u_gamma: Fr::zero(),
    }
}

fn main() {
    let (source, source_sk, source_hidden) = make_instance(5, 0, 0);
    let (paper, paper_sk, paper_hidden) = make_instance(7, 200, 1);

    let source_honest = honest_proof(&source, source_sk, source_hidden);
    let paper_honest = honest_proof(&paper, paper_sk, paper_hidden);
    let candidate = zero_proof();

    let honest_source_accepts = verify(&source, &source_honest);
    let honest_paper_accepts = verify(&paper, &paper_honest);
    let candidate_source_accepts = verify(&source, &candidate);
    let candidate_paper_accepts = verify(&paper, &candidate);

    let (changed_messages, _, _) = make_instance(5, 400, 0);
    let candidate_changed_messages_accepts = verify(&changed_messages, &candidate);
    let mut changed_context = source.clone();
    changed_context.context[30] = 0xa5;
    let candidate_changed_context_accepts = verify(&changed_context, &candidate);

    let mut mutate_a = candidate.clone();
    mutate_a.a_bar = g1();
    let mutate_a_rejects = !verify(&source, &mutate_a);
    let mut mutate_b = candidate.clone();
    mutate_b.b_bar = g1();
    let mutate_b_rejects = !verify(&source, &mutate_b);
    let mut mutate_u = candidate.clone();
    mutate_u.u = g1();
    let mutate_u_rejects = !verify(&source, &mutate_u);
    let mut mutate_s = candidate.clone();
    mutate_s.s = Fr::one();
    let mutate_s_rejects = !verify(&source, &mutate_s);

    let mut honest_changed_message = source.clone();
    honest_changed_message.messages[0] += Fr::one();
    let honest_changed_message_rejects = !verify(&honest_changed_message, &source_honest);

    let all_required = honest_source_accepts
        && honest_paper_accepts
        && candidate_source_accepts
        && candidate_paper_accepts
        && candidate_changed_messages_accepts
        && candidate_changed_context_accepts
        && mutate_a_rejects
        && mutate_b_rejects
        && mutate_u_rejects
        && mutate_s_rejects
        && honest_changed_message_rejects;

    println!("{{");
    println!("  \"profile\": \"CUBE-BN254-M5-AND-PAPER-COMPLETE-KECCAK256-V1\",");
    println!("  \"actual_bn254_pairings\": true,");
    println!("  \"signing_queries\": 0,");
    println!("  \"honest_source_accepts\": {honest_source_accepts},");
    println!("  \"honest_paper_complete_accepts\": {honest_paper_accepts},");
    println!("  \"candidate_source_accepts\": {candidate_source_accepts},");
    println!("  \"candidate_paper_complete_accepts\": {candidate_paper_accepts},");
    println!("  \"candidate_changed_messages_accepts\": {candidate_changed_messages_accepts},");
    println!("  \"candidate_changed_context_accepts\": {candidate_changed_context_accepts},");
    println!("  \"mutate_a_rejects\": {mutate_a_rejects},");
    println!("  \"mutate_b_rejects\": {mutate_b_rejects},");
    println!("  \"mutate_u_rejects\": {mutate_u_rejects},");
    println!("  \"mutate_s_rejects\": {mutate_s_rejects},");
    println!("  \"honest_changed_message_rejects\": {honest_changed_message_rejects},");
    println!("  \"result\": \"{}\"", if all_required { "PASS" } else { "FAIL" });
    println!("}}");

    if !all_required {
        std::process::exit(1);
    }
}
