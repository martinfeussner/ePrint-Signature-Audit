//! JEVIL-EXP-002 signing-oracle stage.
//!
//! This process receives a private seed file and writes only public artifacts:
//! a public key, unique query messages, ordinary signatures, and accounting.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use jevil::{Params, keygen, sign, verify};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

fn sha256(bytes: &[u8]) -> String {
	hex::encode(Sha256::digest(bytes))
}

fn read_seed(path: &Path) -> [u8; 32] {
	let bytes = fs::read(path).expect("read private seed file");
	bytes
		.try_into()
		.expect("private seed file must contain exactly 32 bytes")
}

fn main() {
	let args: Vec<String> = std::env::args().collect();
	assert_eq!(
		args.len(),
		4,
		"usage: exp002_oracle PRIVATE_SEED_FILE PUBLIC_OUTPUT_DIR QUERY_COUNT"
	);
	let seed_path = PathBuf::from(&args[1]);
	let out = PathBuf::from(&args[2]);
	let query_count: usize = args[3].parse().expect("decimal query count");
	assert!((1..=1023).contains(&query_count), "query cap is 1,023");
	assert!(
		!out.exists()
			|| fs::read_dir(&out)
				.expect("read output directory")
				.next()
				.is_none(),
		"public output directory must be absent or empty"
	);
	fs::create_dir_all(out.join("messages")).expect("create message directory");
	fs::create_dir_all(out.join("signatures")).expect("create signature directory");

	let private_seed = read_seed(&seed_path);
	let seed_hash = sha256(&private_seed);
	let params = Params::new(1023);
	let started = Instant::now();
	let mut rng = ChaCha20Rng::from_seed(private_seed);
	let (pk, sk, cache) = keygen(&mut rng, params);
	let pk_bytes = pk.to_bytes();
	fs::write(out.join("public-key.bin"), pk_bytes).expect("write public key");

	let mut corpus_hash = Sha256::new();
	let mut signature_bytes_total: u64 = 0;
	for index in 0..query_count {
		assert!(index < 1023, "the excluded 1,024th response was requested");
		let message = format!(
			"JEVIL-EXP-002/ordinary-query/{index:04}/{}",
			hex::encode(pk.root)
		)
		.into_bytes();
		let signature = sign(&sk, &pk, &cache, params, &message);
		verify(&pk, params, &message, &signature).expect("ordinary self-verification");
		let signature_bytes = signature.to_bytes();
		signature_bytes_total += signature_bytes.len() as u64;

		let message_name = format!("query-{index:04}.msg");
		let signature_name = format!("query-{index:04}.sig");
		fs::write(out.join("messages").join(message_name), &message).expect("write query message");
		fs::write(
			out.join("signatures").join(signature_name),
			&signature_bytes,
		)
		.expect("write ordinary signature");

		corpus_hash.update((index as u32).to_le_bytes());
		corpus_hash.update((message.len() as u64).to_le_bytes());
		corpus_hash.update(&message);
		corpus_hash.update((signature_bytes.len() as u64).to_le_bytes());
		corpus_hash.update(&signature_bytes);
	}

	let mut completion = String::new();
	writeln!(completion, "experiment=JEVIL-EXP-002").unwrap();
	writeln!(completion, "n_star=1023").unwrap();
	writeln!(completion, "poseidon_capacity=4").unwrap();
	writeln!(completion, "query_count={query_count}").unwrap();
	writeln!(completion, "first_zero_based_query_index=0").unwrap();
	writeln!(
		completion,
		"last_zero_based_query_index={}",
		query_count - 1
	)
	.unwrap();
	writeln!(completion, "excluded_zero_based_query_index=1023").unwrap();
	writeln!(completion, "public_key_sha256={}", sha256(&pk_bytes)).unwrap();
	writeln!(completion, "oracle_seed_sha256={seed_hash}").unwrap();
	writeln!(completion, "signature_bytes_total={signature_bytes_total}").unwrap();
	writeln!(
		completion,
		"corpus_sha256={}",
		hex::encode(corpus_hash.finalize())
	)
	.unwrap();
	writeln!(
		completion,
		"elapsed_milliseconds={}",
		started.elapsed().as_millis()
	)
	.unwrap();
	writeln!(completion, "ordinary_self_verification=PASS").unwrap();
	fs::write(out.join("COMPLETE.txt"), completion).expect("write completion record");
}
