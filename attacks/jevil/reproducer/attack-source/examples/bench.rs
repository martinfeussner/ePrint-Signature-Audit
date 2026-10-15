//! Microbenchmark for Jevil's keygen/sign/verify across a sweep of `n_star`.
//!
//! Run with `cargo run --release --example bench`. Add a custom sweep by
//! passing a comma-separated list:
//!
//! ```text
//! cargo run --release --example bench -- 1,3,7,15,31
//! ```
//!
//! Every supplied `n_star` must lie in the recommended regime (`n_star + 1` a
//! power of two), i.e. `{1, 3, 7, 15, 31, 63, 127, 255, 511, 1023, …}`.

use std::env;
use std::time::Instant;

use jevil::{Params, keygen, sign, verify};

fn main() {
	let arg = env::args()
		.nth(1)
		.unwrap_or_else(|| "1,3,7,15,31,63,127,255,511,1023,2047,4095".to_string());
	let n_stars: Vec<u32> = arg
		.split(',')
		.map(|s| s.trim().parse().expect("invalid n_star"))
		.collect();
	for &n_star in &n_stars {
		if n_star == 0 || ((n_star + 1) & n_star) != 0 {
			eprintln!(
				"error: n_star + 1 must be a power of two; got n_star = {n_star}.\n\
				 valid values: 1, 3, 7, 15, 31, 63, 127, 255, 511, 1023, …"
			);
			std::process::exit(2);
		}
	}

	println!(
		"{:>8} {:>10} {:>10} {:>11} {:>10} {:>11} {:>10}",
		"n*", "M", "N", "keygen_ms", "sign_ms", "verify_ms", "sig_bytes"
	);
	println!("{}", "-".repeat(73));

	for n_star in n_stars {
		let params = Params::new(n_star);
		// Fresh OS entropy per iteration so the timings reflect real keys,
		// not a single recycled seed.
		let mut rng = rand::rng();

		let t0 = Instant::now();
		let (pk, sk, cache) = keygen(&mut rng, params);
		let keygen_ms = t0.elapsed().as_secs_f64() * 1000.0;

		let msg = b"bench-msg";
		let t0 = Instant::now();
		let sig = sign(&sk, &pk, &cache, params, msg);
		let sign_ms = t0.elapsed().as_secs_f64() * 1000.0;

		let t0 = Instant::now();
		verify(&pk, params, msg, &sig).expect("verify");
		let verify_ms = t0.elapsed().as_secs_f64() * 1000.0;

		println!(
			"{:>8} {:>10} {:>10} {:>11.2} {:>10.3} {:>11.3} {:>10}",
			n_star,
			params.m(),
			params.n(),
			keygen_ms,
			sign_ms,
			verify_ms,
			sig.to_bytes().len()
		);
	}
}
