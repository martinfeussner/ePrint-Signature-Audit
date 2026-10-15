#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export MKL_NUM_THREADS=1
PYTHON="${PYTHON:-python3}"

mode="${1:-}"
case "$mode" in
  --smoke)
    make -j1 build/bin/selftest
    (
      ulimit -v 4194304
      exec ./build/bin/selftest
    )
    cat <<'EOF'
EAGLESIGNV3 STRUCTURE SMOKE: PASS
EOF
    ;;
  --full)
    for command in g++ "$PYTHON" taskset sha256sum /usr/bin/time; do
      command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 2
      }
    done
    "$PYTHON" -c 'import numpy, scipy' || {
      echo "Python dependencies are missing; install requirements.txt" >&2
      exit 2
    }
    if [[ -e output/full ]]; then
      echo "output/full already exists; run 'make clean' before a new full run" >&2
      exit 2
    fi
    make -j1 build
    mkdir -p output/full
    run_root="$(mktemp -d "${TMPDIR:-/tmp}/eaglesignv3-public-reproducer.XXXXXX")"
    cleanup() {
      chmod -R u+rwX "$run_root" 2>/dev/null || true
      rm -rf "$run_root"
    }
    trap cleanup EXIT
    mkdir -p "$run_root/private/key-attempts" \
      "$run_root/public/key-attempts" "$run_root/work" "$run_root/logs"
    dd if=/dev/urandom of="$run_root/private/target-seed.bin" \
      bs=32 count=1 status=none
    chmod 600 "$run_root/private/target-seed.bin"
    solver_cpu="$(awk -F':[	 ]*' '/^Cpus_allowed_list:/{print $2}' /proc/self/status | cut -d, -f1 | cut -d- -f1)"
    if [[ ! "$solver_cpu" =~ ^[0-9]+$ ]]; then
      echo "could not determine one allowed CPU for sealed solver affinity" >&2
      exit 2
    fi
    printf '%s\n' "$solver_cpu" >"$run_root/public/solver-cpu.txt"

    run_limited() {
      local timing="$1"
      shift
      (
        ulimit -v 4194304
        exec /usr/bin/time -v -o "$timing" "$@"
      )
    }

    run_limited "$run_root/logs/keygen.time" \
      ./build/bin/keygen "$run_root/private/target-seed.bin" "$run_root" \
      >"$run_root/logs/keygen.stdout" 2>"$run_root/logs/keygen.stderr"
    run_limited "$run_root/logs/oracle.time" \
      ./build/bin/oracle "$run_root/private/selected_secret_key.bin" \
        "$run_root/public/public_key.bin" "$run_root/public/transcripts.bin" \
        40000 "$run_root/public/oracle-summary.txt" \
      >"$run_root/logs/oracle.stdout" 2>"$run_root/logs/oracle.stderr"
    run_limited "$run_root/logs/recover-prepare.time" \
      ./build/bin/recover prepare "$run_root/public/public_key.bin" \
        "$run_root/public/transcripts.bin" "$run_root/work/constraints.lp" \
        "$run_root/public/constraint-report.txt" \
      >"$run_root/logs/recover-prepare.stdout" \
      2>"$run_root/logs/recover-prepare.stderr"
    run_limited "$run_root/logs/milp.time" \
      taskset -c "$solver_cpu" "$PYTHON" -B solve_milp.py \
        "$run_root/work/constraints.lp" \
        "$run_root/work/milp-solution.txt" \
        "$run_root/public/solver-report.json" \
        --time-limit 21600 --threads 1 \
      >"$run_root/logs/milp.stdout" 2>"$run_root/logs/milp.stderr"
    run_limited "$run_root/logs/recover-finalize.time" \
      ./build/bin/recover finalize "$run_root/public/public_key.bin" \
        "$run_root/public/transcripts.bin" "$run_root/work/milp-solution.txt" \
        "$run_root/public/recovered_key.bin" "$run_root/public/forgery.bin" \
        "$run_root/public/recovery-report.txt" \
      >"$run_root/logs/recover-finalize.stdout" \
      2>"$run_root/logs/recover-finalize.stderr"
    run_limited "$run_root/logs/verify.time" \
      ./build/bin/verify "$run_root/public/public_key.bin" \
        "$run_root/public/transcripts.bin" "$run_root/public/recovered_key.bin" \
        "$run_root/public/forgery.bin" "$run_root/public/verification-report.txt" \
      >"$run_root/logs/verify.stdout" 2>"$run_root/logs/verify.stderr"

    # Ground truth is consulted only after all public recovery and verifier
    # checks above have exited successfully.
    run_limited "$run_root/logs/ground-truth.time" \
      ./build/bin/compare_ground_truth \
        "$run_root/private/selected_secret_key.bin" \
        "$run_root/public/recovered_key.bin" \
        "$run_root/private/ground-truth-comparison.txt" \
      >"$run_root/logs/ground-truth.stdout" \
      2>"$run_root/logs/ground-truth.stderr"

    cp "$run_root/public/keygen-summary.txt" output/full/
    cp "$run_root/public/key-attempts.tsv" output/full/
    cp "$run_root/public/oracle-summary.txt" output/full/
    cp "$run_root/public/constraint-report.txt" output/full/
    cp "$run_root/public/solver-report.json" output/full/
    cp "$run_root/public/solver-cpu.txt" output/full/
    cp "$run_root/public/recovery-report.txt" output/full/
    cp "$run_root/public/verification-report.txt" output/full/
    cp "$run_root/private/ground-truth-comparison.txt" output/full/
    cp "$run_root/logs/"*.time output/full/
    cp "$run_root/logs/"*.stdout output/full/
    cp "$run_root/logs/"*.stderr output/full/
    (
      cd output/full
      find . -type f ! -name MANIFEST.sha256 -print0 | \
        LC_ALL=C sort -z | xargs -0 sha256sum > MANIFEST.sha256
    )

    runtime="$(awk -F': ' '/Elapsed \(wall clock\) time/{print $2}' \
      output/full/recover-finalize.time)"
    peak="$(awk -F': ' '/Maximum resident set size/{print $2 " KiB"}' \
      output/full/milp.time)"
    cat <<EOF
========================================
EAGLESIGNV3 FULL ATTACK REPRODUCTION: PASS

Target: paper-level Ring-L2
Printed signer outputs: 40000
Result: D and equivalent signing key G recovered
Fresh-message forgery: ACCEPTED
Changed-message control: REJECTED
Altered-signature control: REJECTED
Recovery-finalize runtime: ${runtime}
MILP peak RAM: ${peak}
Trial scope: one freshly generated unit-T key
========================================
EOF
    ;;
  *)
    echo "usage: ./reproduce.sh --smoke|--full" >&2
    exit 2
    ;;
esac

