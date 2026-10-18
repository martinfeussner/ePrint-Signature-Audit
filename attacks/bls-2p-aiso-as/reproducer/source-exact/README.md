# Source-exact BLS12-381 verifier reproduction

This harness tests only the chosen-key `DS2` interface in Definition 33 of
ePrint 2026/1394. It imports the paper-linked artifact's unchanged
`bls-aiso-as` crate, obtains the honest public key from its `BLSKeyPair::new`,
aggregates by the same direct G1 addition used by the artifact, hashes with
the artifact's SHA-256 XMD `hash_to_g2`, and calls its ordinary public
`bls::verify` function.

The script downloads the official Anonymous GitHub ZIP unless an already
downloaded copy is provided. Before compiling anything, it verifies the ZIP
SHA-256 and the hashes of the six relevant source files. The ZIP is pinned as:

```text
f1e70afef59a55e3a852d1a9debfefb7f9250f90679a65faa46ecdf0c0a7b441
```

The anonymous mirror exposes no Git revision. The ZIP hash and source hashes
are therefore the source identity; no commit or tree identity is claimed.

Run with Bash, `curl`, `unzip`, `sha256sum`, and Rust/Cargo 1.85 or later:

```sh
./reproduce-source-exact.sh
```

To avoid a download, point to a local byte-identical ZIP:

```sh
BLS_AISO_AS_ARTIFACT_ZIP=/path/to/author-artifact.zip \
  CARGO_NET_OFFLINE=true ./reproduce-source-exact.sh
```

Cargo uses the included lock file, one build job, one Rayon worker, and a
1 GiB virtual-memory limit. A first run may need network access to fetch the
locked Rust dependencies. `CARGO_NET_OFFLINE=true` works after those crates
are present in the Cargo cache.

This is an exact-verifier diagnostic. The artifact's normal application
programs generate both keypairs honestly, and this harness deliberately does
not claim conformance to that lifecycle, Figure 6, a proper DKG, or any
deployment.
