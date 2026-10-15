//! JEVIL-EXP-002 public-data recovery and fresh-forgery stage.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use jevil::{
	Goldilocks4, Params, PublicKey, RecoveredSigner, RecoveryError, Signature,
	interpolate_four_rows, verify, verify_and_observe_initial,
};
use rand::Rng;
use sha2::{Digest, Sha256};

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
	Sha256::digest(bytes).into()
}

fn sha256_hex(bytes: &[u8]) -> String {
	hex::encode(sha256_bytes(bytes))
}

fn read_fixed<const N: usize>(path: &Path) -> [u8; N] {
	fs::read(path)
		.expect("read fixed-size file")
		.try_into()
		.unwrap_or_else(|v: Vec<u8>| {
			panic!("{}: expected {N} bytes, got {}", path.display(), v.len())
		})
}

fn completion_value<'a>(completion: &'a str, key: &str) -> &'a str {
	completion
		.lines()
		.find_map(|line| line.strip_prefix(&format!("{key}=")))
		.unwrap_or_else(|| panic!("missing completion key {key}"))
}

fn write_row(path: &Path, row: &[Goldilocks4]) {
	let mut bytes = Vec::with_capacity(row.len() * 32);
	for value in row {
		bytes.extend_from_slice(&value.to_bytes());
	}
	fs::write(path, bytes).expect("write recovered row");
}

fn main() {
	let args: Vec<String> = std::env::args().collect();
	assert_eq!(
		args.len(),
		3,
		"usage: exp002_recover PUBLIC_TRANSCRIPT_DIR RESULT_DIR"
	);
	let public_dir = PathBuf::from(&args[1]);
	let result_dir = PathBuf::from(&args[2]);
	assert!(
		!result_dir.exists()
			|| fs::read_dir(&result_dir)
				.expect("read result directory")
				.next()
				.is_none(),
		"result directory must be absent or empty"
	);
	fs::create_dir_all(&result_dir).expect("create result directory");
	let started = Instant::now();

	let completion =
		fs::read_to_string(public_dir.join("COMPLETE.txt")).expect("read oracle completion record");
	assert_eq!(completion_value(&completion, "experiment"), "JEVIL-EXP-002");
	assert_eq!(completion_value(&completion, "n_star"), "1023");
	let query_count: usize = completion_value(&completion, "query_count")
		.parse()
		.expect("query count");
	assert!((1..=1023).contains(&query_count));
	let last_index: usize = completion_value(&completion, "last_zero_based_query_index")
		.parse()
		.expect("last query index");
	assert_eq!(last_index + 1, query_count);
	assert!(
		last_index < 1023,
		"the excluded 1,024th response is present"
	);

	let pk_bytes = read_fixed::<68>(&public_dir.join("public-key.bin"));
	let pk = PublicKey::from_bytes(&pk_bytes).expect("parse public key");
	let params = Params::new(1023);
	assert_eq!(pk.n_star, 1023);
	assert_eq!(
		sha256_hex(&pk_bytes),
		completion_value(&completion, "public_key_sha256")
	);

	let mut openings: BTreeMap<u32, [Goldilocks4; 4]> = BTreeMap::new();
	let mut messages: HashSet<Vec<u8>> = HashSet::new();
	let mut signature_hashes: HashSet<[u8; 32]> = HashSet::new();
	let mut authenticated_opening_count = 0usize;
	let mut signature_bytes_total = 0u64;
	let mut corpus_hash = Sha256::new();
	for index in 0..query_count {
		let message = fs::read(
			public_dir
				.join("messages")
				.join(format!("query-{index:04}.msg")),
		)
		.expect("read query message");
		assert!(messages.insert(message.clone()), "duplicate query message");
		let signature_bytes = fs::read(
			public_dir
				.join("signatures")
				.join(format!("query-{index:04}.sig")),
		)
		.expect("read ordinary signature");
		signature_bytes_total += signature_bytes.len() as u64;
		signature_hashes.insert(sha256_bytes(&signature_bytes));
		corpus_hash.update((index as u32).to_le_bytes());
		corpus_hash.update((message.len() as u64).to_le_bytes());
		corpus_hash.update(&message);
		corpus_hash.update((signature_bytes.len() as u64).to_le_bytes());
		corpus_hash.update(&signature_bytes);
		let signature = Signature::from_bytes(&signature_bytes).expect("parse ordinary signature");
		let observed = verify_and_observe_initial(&pk, params, &message, &signature)
			.expect("unchanged ordinary verification and authenticated observation");
		assert_eq!(observed.len(), 64);
		authenticated_opening_count += observed.len();
		for opening in observed {
			match openings.get(&opening.position) {
				Some(existing) if existing != &opening.symbols => {
					panic!("{}", RecoveryError::ConflictingOpening)
				}
				Some(_) => {}
				None => {
					openings.insert(opening.position, opening.symbols);
				}
			}
		}
		if matches!(index + 1, 160 | 320 | 480 | 650) {
			eprintln!(
				"RECOVERY_MILESTONE records={} distinct_positions={}",
				index + 1,
				openings.len()
			);
		}
	}
	assert_eq!(
		signature_bytes_total.to_string(),
		completion_value(&completion, "signature_bytes_total")
	);
	assert_eq!(
		hex::encode(corpus_hash.finalize()),
		completion_value(&completion, "corpus_sha256")
	);
	assert!(
		openings.len() >= 32_768,
		"not enough distinct authenticated positions"
	);

	let mut opening_bytes = Vec::with_capacity(openings.len() * (4 + 4 * 32));
	for (&position, values) in &openings {
		opening_bytes.extend_from_slice(&position.to_le_bytes());
		for value in values {
			opening_bytes.extend_from_slice(&value.to_bytes());
		}
	}
	fs::write(
		result_dir.join("authenticated-openings.bin"),
		&opening_bytes,
	)
	.expect("write opening transcript");

	let rows = interpolate_four_rows(&openings, 32_768, 131_072)
		.expect("independent four-row interpolation and full re-encode");
	let mut row_hashes = Vec::new();
	for (index, row) in rows.iter().enumerate() {
		let path = result_dir.join(format!("recovered-row-{index}.bin"));
		write_row(&path, row);
		row_hashes.push(sha256_hex(&fs::read(path).expect("read row for hashing")));
	}

	let mut fresh_randomness = [0u8; 32];
	rand::rng().fill_bytes(&mut fresh_randomness);
	let fresh_randomness_hash = sha256_hex(&fresh_randomness);
	assert_ne!(
		fresh_randomness_hash,
		completion_value(&completion, "oracle_seed_sha256"),
		"fresh randomness unexpectedly equals oracle seed"
	);
	let recovered = RecoveredSigner::from_rows(&rows, &pk, params, fresh_randomness)
		.expect("recovered rows reproduce root and public evaluation");

	let fresh_message = format!(
		"JEVIL-EXP-002/fresh-unqueried-forgery/{}",
		hex::encode(pk.root)
	)
	.into_bytes();
	assert!(
		!messages.contains(&fresh_message),
		"fresh message was queried"
	);
	let fresh_signature = recovered.sign(&fresh_message);
	verify(&pk, params, &fresh_message, &fresh_signature)
		.expect("unchanged ordinary verifier accepts fresh signature");
	let fresh_signature_bytes = fresh_signature.to_bytes();
	assert!(
		!signature_hashes.contains(&sha256_bytes(&fresh_signature_bytes)),
		"fresh signature duplicates an oracle response"
	);

	let mut changed_message = fresh_message.clone();
	changed_message.push(0xff);
	let changed_message_rejected = verify(&pk, params, &changed_message, &fresh_signature).is_err();
	assert!(changed_message_rejected);

	let mut changed_pk = pk.clone();
	changed_pk.root[0] ^= 1;
	let changed_root_rejected =
		verify(&changed_pk, params, &fresh_message, &fresh_signature).is_err();
	assert!(changed_root_rejected);

	let mut altered_signature_bytes = fresh_signature_bytes.clone();
	let last = altered_signature_bytes.len() - 1;
	altered_signature_bytes[last] ^= 1;
	let altered_signature_rejected = match Signature::from_bytes(&altered_signature_bytes) {
		Ok(altered) => verify(&pk, params, &fresh_message, &altered).is_err(),
		Err(_) => true,
	};
	assert!(altered_signature_rejected);

	let mut corrupted_rows = rows.clone();
	corrupted_rows[0][0] += Goldilocks4::ONE;
	let corrupted_row_rejected =
		RecoveredSigner::from_rows(&corrupted_rows, &pk, params, [0x5a; 32]).is_err();
	assert!(corrupted_row_rejected);

	fs::write(result_dir.join("fresh-message.bin"), &fresh_message).expect("write fresh message");
	fs::write(
		result_dir.join("fresh-signature.bin"),
		&fresh_signature_bytes,
	)
	.expect("write fresh signature");
	fs::write(result_dir.join("public-key.bin"), pk_bytes).expect("copy public key");

	let mut result = String::new();
	writeln!(result, "{{").unwrap();
	writeln!(
		result,
		"  \"schema\": \"org.eprint-signature-audit.jevil-width-four-result/v1\","
	)
	.unwrap();
	writeln!(result, "  \"mode\": \"full\",").unwrap();
	writeln!(result, "  \"experiment\": \"JEVIL-EXP-002\",").unwrap();
	writeln!(result, "  \"verdict\": \"PASS\",").unwrap();
	writeln!(result, "  \"n_star\": 1023,").unwrap();
	writeln!(result, "  \"query_count\": {query_count},").unwrap();
	writeln!(
		result,
		"  \"maximum_zero_based_query_index\": {last_index},"
	)
	.unwrap();
	writeln!(result, "  \"excluded_1024th_signature_unused\": true,").unwrap();
	writeln!(
		result,
		"  \"authenticated_openings\": {authenticated_opening_count},"
	)
	.unwrap();
	writeln!(result, "  \"distinct_positions\": {},", openings.len()).unwrap();
	writeln!(
		result,
		"  \"signature_bytes_total\": {signature_bytes_total},"
	)
	.unwrap();
	writeln!(
		result,
		"  \"public_key_sha256\": \"{}\",",
		sha256_hex(&pk_bytes)
	)
	.unwrap();
	writeln!(
		result,
		"  \"opening_transcript_sha256\": \"{}\",",
		sha256_hex(&opening_bytes)
	)
	.unwrap();
	writeln!(result, "  \"row_sha256\": [").unwrap();
	for (index, hash) in row_hashes.iter().enumerate() {
		let comma = if index + 1 == row_hashes.len() {
			""
		} else {
			","
		};
		writeln!(result, "    \"{hash}\"{comma}").unwrap();
	}
	writeln!(result, "  ],").unwrap();
	writeln!(result, "  \"root_reconstructed\": true,").unwrap();
	writeln!(result, "  \"public_evaluation_reconstructed\": true,").unwrap();
	writeln!(result, "  \"fresh_message_unqueried\": true,").unwrap();
	writeln!(
		result,
		"  \"fresh_randomness_sha256\": \"{fresh_randomness_hash}\","
	)
	.unwrap();
	writeln!(
		result,
		"  \"fresh_message_sha256\": \"{}\",",
		sha256_hex(&fresh_message)
	)
	.unwrap();
	writeln!(
		result,
		"  \"fresh_signature_bytes\": {},",
		fresh_signature_bytes.len()
	)
	.unwrap();
	writeln!(
		result,
		"  \"fresh_signature_sha256\": \"{}\",",
		sha256_hex(&fresh_signature_bytes)
	)
	.unwrap();
	writeln!(result, "  \"unchanged_verifier_accepts_forgery\": true,").unwrap();
	writeln!(
		result,
		"  \"changed_message_rejected\": {changed_message_rejected},"
	)
	.unwrap();
	writeln!(
		result,
		"  \"changed_root_rejected\": {changed_root_rejected},"
	)
	.unwrap();
	writeln!(
		result,
		"  \"altered_signature_rejected\": {altered_signature_rejected},"
	)
	.unwrap();
	writeln!(
		result,
		"  \"corrupted_row_rejected\": {corrupted_row_rejected},"
	)
	.unwrap();
	writeln!(result, "  \"public_inputs_only\": true,").unwrap();
	writeln!(
		result,
		"  \"elapsed_milliseconds\": {}",
		started.elapsed().as_millis()
	)
	.unwrap();
	writeln!(result, "}}").unwrap();
	fs::write(result_dir.join("result.json"), result).expect("write result JSON");
}
