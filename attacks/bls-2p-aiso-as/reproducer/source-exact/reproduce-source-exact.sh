#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
artifact_url="https://anonymous.4open.science/api/repo/Adaptor_Signatures_Meet_BLS-ECD0/zip"
artifact_sha256="f1e70afef59a55e3a852d1a9debfefb7f9250f90679a65faa46ecdf0c0a7b441"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bls-definition33-source-exact.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

artifact_zip="$work_dir/author-artifact.zip"
if [[ -n "${BLS_AISO_AS_ARTIFACT_ZIP:-}" ]]; then
    cp "$BLS_AISO_AS_ARTIFACT_ZIP" "$artifact_zip"
else
    command -v curl >/dev/null || {
        echo "curl is required unless BLS_AISO_AS_ARTIFACT_ZIP is set" >&2
        exit 2
    }
    curl --fail --location --silent --show-error \
        "$artifact_url" --output "$artifact_zip"
fi

printf '%s  %s\n' "$artifact_sha256" "$artifact_zip" | sha256sum --check --status || {
    echo "official artifact ZIP hash mismatch" >&2
    exit 2
}

mkdir -p "$work_dir/upstream" "$work_dir/harness"
unzip -q "$artifact_zip" -d "$work_dir/upstream"

(
    cd "$work_dir/upstream"
    cat > "$work_dir/relevant-source.sha256" <<'EOF'
f26362cdb3eb14485e62a6fd7085ffb58cdd0597013f52a39b260de7d49de52e  bls-aiso-as/src/bls.rs
cd7a2d0498f1f62ed8679e70440c9c3b2057f3cd8094ebd5d87d557a1c188344  bls-aiso-as/src/common.rs
bef2c4fb6a0f6b2de5fbdbf4fdf390a58ea81daa0a4c6bc4fbd0ef8b67b50d12  test-as/src/main.rs
e33790341c5ad68095dcb6808b7a0232938d49edf3104a81034faeb57889dadf  test-as-optimized/src/main.rs
ede88455d5b3aa6f2622ccef216119a3043f4397cbcda02d9ab31cc7960c8488  Cargo.toml
a0323e6d9193c48126207db90ad5718d03a71f174b8c902f929ace00c4261a6f  bls-aiso-as/Cargo.toml
EOF
    sha256sum --check --strict "$work_dir/relevant-source.sha256"
)

cp "$script_dir/harness/Cargo.toml" "$work_dir/harness/Cargo.toml"
cp "$script_dir/harness/Cargo.lock" "$work_dir/harness/Cargo.lock"
mkdir -p "$work_dir/harness/src"
cp "$script_dir/harness/src/main.rs" "$work_dir/harness/src/main.rs"

export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR="$work_dir/target"
export RAYON_NUM_THREADS=1
export RUST_BACKTRACE=0
ulimit -v 1048576

cargo run --quiet --release --locked \
    --manifest-path "$work_dir/harness/Cargo.toml" \
    > "$work_dir/actual-output.txt"

cmp "$work_dir/actual-output.txt" "$script_dir/reference-output.txt"
cat "$work_dir/actual-output.txt"
