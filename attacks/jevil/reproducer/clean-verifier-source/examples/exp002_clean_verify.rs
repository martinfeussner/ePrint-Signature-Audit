//! External acceptance and negative controls against the untouched upstream
//! Jevil library source.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use jevil::{Params, PublicKey, Signature, verify};

fn fixed<const N: usize>(path: &Path) -> [u8; N] {
	fs::read(path)
		.expect("read fixed-size input")
		.try_into()
		.unwrap_or_else(|v: Vec<u8>| panic!("expected {N} bytes, got {}", v.len()))
}

fn main() {
	let args: Vec<String> = std::env::args().collect();
	assert_eq!(
		args.len(),
		5,
		"usage: exp002_clean_verify PK MSG SIG RESULT_JSON"
	);
	let pk = PublicKey::from_bytes(&fixed::<68>(Path::new(&args[1]))).expect("parse public key");
	let message = fs::read(&args[2]).expect("read fresh message");
	let signature_bytes = fs::read(&args[3]).expect("read fresh signature");
	let signature = Signature::from_bytes(&signature_bytes).expect("parse fresh signature");
	let params = Params::new(1023);

	verify(&pk, params, &message, &signature).expect("clean ordinary verifier accepts forgery");

	let mut changed_message = message.clone();
	changed_message.push(0xff);
	assert!(verify(&pk, params, &changed_message, &signature).is_err());

	let mut changed_pk = pk.clone();
	changed_pk.root[0] ^= 1;
	assert!(verify(&changed_pk, params, &message, &signature).is_err());

	let mut altered_bytes = signature_bytes;
	let last = altered_bytes.len() - 1;
	altered_bytes[last] ^= 1;
	let altered_rejected = match Signature::from_bytes(&altered_bytes) {
		Ok(altered) => verify(&pk, params, &message, &altered).is_err(),
		Err(_) => true,
	};
	assert!(altered_rejected);

	let mut result = String::new();
	writeln!(result, "{{").unwrap();
	writeln!(
		result,
		"  \"schema\": \"org.eprint-signature-audit.jevil-clean-verifier-result/v1\","
	)
	.unwrap();
	writeln!(result, "  \"n_star\": 1023,").unwrap();
	writeln!(result, "  \"ordinary_verifier_accepts_forgery\": true,").unwrap();
	writeln!(result, "  \"changed_message_rejected\": true,").unwrap();
	writeln!(result, "  \"changed_root_rejected\": true,").unwrap();
	writeln!(result, "  \"altered_signature_rejected\": true").unwrap();
	writeln!(result, "}}").unwrap();
	fs::write(&args[4], result).expect("write verifier result JSON");

	println!("CLEAN_ORDINARY_VERIFIER_ACCEPTS_FRESH_FORGERY=PASS");
	println!("CLEAN_CHANGED_MESSAGE_REJECTED=PASS");
	println!("CLEAN_CHANGED_ROOT_REJECTED=PASS");
	println!("CLEAN_ALTERED_SIGNATURE_REJECTED=PASS");
}
