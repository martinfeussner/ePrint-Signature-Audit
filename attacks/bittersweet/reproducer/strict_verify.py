#!/usr/bin/env python3
"""Independent strict verifier for the Bittersweet full-L1 reproduction.

This file does not import the signer, recovery solver, instance generator, or
private truth.  It independently decodes the compressed Section 7.1 response,
reconstructs every opened key/output/commitment and hidden output, checks the
Figure 3 modular predicate, and recomputes the Fiat--Shamir challenge.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
from typing import Any, Iterable, Sequence


DOMAIN = b"Bittersweet-v1-expanded-matrix-full-L1-reproduction"
PDF_SHA = "eefe27b903cb61fa50fecc33eef3fa99b121bece1c9831a4b3cab7bdebba5dbb"
QB, PB, AB, P_BITS, NCOLS, NROWS, PARTIES, REPS = 96, 3, 90, 93, 11, 747, 32, 26
MODQ, MODP = 1 << QB, 1 << PB
MASKQ = MODQ - 1
MODEL_SCOPE = (
    "Canonical random-oracle/XOF realization of exact ePrint 2026/397 v1 "
    "mathematics; no normative v1 wire format or public implementation exists."
)
SIGNATURE_PARAMETERS = {
    "q": QB,
    "p_prime": PB,
    "alpha": AB,
    "p": P_BITS,
    "n": NCOLS,
    "m": NROWS,
    "d": PARTIES,
    "t": REPS,
}


def canonical(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def be32(number: int) -> bytes:
    return number.to_bytes(4, "big")


def frame(blob: bytes) -> bytes:
    return be32(len(blob)) + blob


def word(number: int, size: int) -> bytes:
    if type(number) is not int or not 0 <= number < 1 << (8 * size):
        raise ValueError("integer outside canonical word")
    return number.to_bytes(size, "big")


def vector(numbers: Sequence[int], size: int) -> bytes:
    return be32(len(numbers)) + b"".join(word(x, size) for x in numbers)


def shake(tag: bytes, values: Iterable[bytes], length: int) -> bytes:
    state = hashlib.shake_256()
    state.update(frame(DOMAIN))
    state.update(frame(tag))
    for value in values:
        state.update(frame(value))
    return state.digest(length)


def encode_matrix(a: Sequence[Sequence[int]]) -> bytes:
    result = bytearray(be32(len(a)))
    for row in a:
        result.extend(vector(row, 12))
    return bytes(result)


def bind_matrix(a: Sequence[Sequence[int]]) -> bytes:
    return hashlib.sha3_256(frame(DOMAIN) + frame(b"expanded-public-matrix") + frame(encode_matrix(a))).digest()


def expand_public_matrix(public_seed: bytes) -> list[list[int]]:
    """Canonical public XOF expansion used by the fresh-key validation run."""
    raw = shake(b"public-matrix-G", (public_seed,), NROWS * NCOLS * 12)
    values = [int.from_bytes(raw[i : i + 12], "big") for i in range(0, len(raw), 12)]
    return [values[i * NCOLS : (i + 1) * NCOLS] for i in range(NROWS)]


def multiply(a: Sequence[Sequence[int]], x: Sequence[int]) -> list[int]:
    if len(x) != NCOLS:
        raise ValueError("wrong key-vector length")
    return [sum(coefficient * value for coefficient, value in zip(row, x)) & MASKQ for row in a]


def rounded(values: Sequence[int]) -> list[int]:
    return [x >> 93 for x in values]


def split_node(seed: bytes, level: int, index: int) -> tuple[bytes, bytes]:
    block = shake(b"GGM-child", (seed, word(level, 2), word(index, 4)), 32)
    return block[:16], block[16:]


def expand_subtree(seed: bytes, level: int, index: int, destination: dict[int, bytes]) -> None:
    if level == 5:
        destination[index] = seed
        return
    left, right = split_node(seed, level, index)
    expand_subtree(left, level + 1, 2 * index, destination)
    expand_subtree(right, level + 1, 2 * index + 1, destination)


def expand_root(root: bytes) -> dict[int, bytes]:
    result: dict[int, bytes] = {}
    expand_subtree(root, 0, 0, result)
    if set(result) != set(range(PARTIES)):
        raise AssertionError("bad complete GGM expansion")
    return result


def expand_copath(path: Sequence[bytes], hidden: int) -> dict[int, bytes]:
    if len(path) != 5 or not 0 <= hidden < PARTIES:
        raise ValueError("bad GGM copath")
    result: dict[int, bytes] = {}
    node = 0
    for level, sibling_seed in enumerate(path):
        if len(sibling_seed) != 16:
            raise ValueError("bad sibling seed")
        bit = (hidden >> (4 - level)) & 1
        sibling = 2 * node + (1 - bit)
        expand_subtree(sibling_seed, level + 1, sibling, result)
        node = 2 * node + bit
    if set(result) != set(range(PARTIES)) - {hidden}:
        raise ValueError("copath opens wrong leaf set")
    return result


def share_from_leaf(seed: bytes, party: int, repetition: int, salt: bytes) -> list[int]:
    raw = shake(b"G2-key-share", (seed, word(party, 2), word(repetition, 2), salt), NCOLS * 12)
    return [int.from_bytes(raw[offset : offset + 12], "big") for offset in range(0, len(raw), 12)]


def key_commitment(key: Sequence[int], party: int, repetition: int, salt: bytes) -> bytes:
    material = (
        frame(DOMAIN)
        + frame(b"H1-key-commitment")
        + frame(vector(key, 12))
        + word(party, 2)
        + word(repetition, 2)
        + frame(salt)
    )
    return hashlib.sha3_256(material).digest()


def decode_hex(text: Any, byte_length: int, label: str) -> bytes:
    if not isinstance(text, str) or len(text) != 2 * byte_length or text.lower() != text:
        raise ValueError(f"noncanonical {label}")
    try:
        value = bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError(f"nonhex {label}") from exc
    if len(value) != byte_length:
        raise ValueError(f"wrong {label} length")
    return value


def decode_errors(text: Any) -> list[int]:
    raw = decode_hex(text, (NROWS + 7) // 8, "packed error vector")
    # 747 bits occupy 94 bytes and leave exactly five unused low bits.  Reject
    # every nonzero pattern in that complete 0x1f padding mask.
    if raw[-1] & 0x1F:
        raise ValueError("nonzero error-vector padding")
    return [(raw[i // 8] >> (7 - i % 8)) & 1 for i in range(NROWS)]


def derive_challenge(digest_value: bytes) -> list[int]:
    value = int.from_bytes(digest_value, "big") >> 126
    return [(value >> (5 * (REPS - 1 - i))) & 31 for i in range(REPS)]


def hash_first_message(
    party_outputs: Sequence[Sequence[Sequence[int]]],
    party_commitments: Sequence[Sequence[bytes]],
    message: bytes,
    matrix_binding: bytes,
    public_y: Sequence[int],
    salt: bytes,
) -> bytes:
    state = hashlib.sha3_256()
    state.update(frame(DOMAIN))
    state.update(frame(b"H2-first-message"))
    for repetition in range(REPS):
        for party in range(PARTIES):
            state.update(vector(party_outputs[repetition][party], 1))
        for party in range(PARTIES):
            state.update(party_commitments[repetition][party])
    state.update(frame(message))
    state.update(frame(matrix_binding))
    state.update(vector(public_y, 1))
    state.update(frame(salt))
    return state.digest()


def parse_public(public: dict[str, Any]) -> tuple[list[list[int]], list[int]]:
    schema = public.get("schema")
    if schema not in {
        "bittersweet-l1-public-interval-instance-v1",
        "bittersweet-v1-full-signature-public-key-v1",
    }:
        raise ValueError("wrong public schema")
    params = public.get("parameters", {})
    actual = tuple(
        int(params.get(k, -1))
        for k in ("q", "p_prime", "alpha", "p", "n", "m", "d", "t")
    )
    if actual != (QB, PB, AB, P_BITS, NCOLS, NROWS, PARTIES, REPS):
        raise ValueError("wrong full-L1 d32 parameters")
    if public.get("target", {}).get("pdf_sha256") != PDF_SHA:
        raise ValueError("wrong target PDF")
    encoded = public.get("matrix_X_hex", [])
    if len(encoded) != NROWS or any(not isinstance(row, list) or len(row) != NCOLS for row in encoded):
        raise ValueError("bad public matrix dimensions")
    matrix = []
    for row in encoded:
        if any(not isinstance(x, str) or len(x) != 24 or x.lower() != x for x in row):
            raise ValueError("noncanonical public matrix word")
        matrix.append([int(x, 16) for x in row])
    public_seed = decode_hex(public.get("public_x_hex"), 16, "public XOF seed")
    if matrix != expand_public_matrix(public_seed):
        raise ValueError("expanded public matrix does not match public XOF seed")
    if schema == "bittersweet-l1-public-interval-instance-v1":
        rows = public.get("rows", [])
        if len(rows) != NROWS:
            raise ValueError("bad public-y row count")
        y = [int(row["public_y"]) for row in rows]
    else:
        y = [int(value) for value in public.get("public_y", [])]
        if len(y) != NROWS:
            raise ValueError("bad public-y vector length")
    if any(not 0 <= value < MODP for value in y):
        raise ValueError("bad public y")
    return matrix, y


def verify(
    public: dict[str, Any],
    public_raw: bytes,
    message: bytes,
    envelope: dict[str, Any],
    *,
    collect_observations: bool = False,
) -> dict[str, Any]:
    outcome: dict[str, Any] = {"accepted": False, "reason": "uninitialized"}
    try:
        if public_raw != canonical(public):
            raise ValueError("public object does not match canonical public bytes")
        recovery_top = {
            "schema", "target_pdf_sha256", "model_scope", "parameters",
            "public_instance", "public_instance_sha256", "public_matrix_binding_hex",
            "public_freeze", "public_freeze_sha256", "recovered_key_sha256",
            "message_sha256", "message_length", "sign_attempts", "abort_count",
            "root_case_count", "path_case_count", "error_zero_count", "error_one_count",
            "mathematical_payload_bits", "mathematical_payload_bytes_ceiling",
            "first_message_hash_hex", "signature",
        }
        oracle_top = {
            "schema", "target_pdf_sha256", "model_scope", "parameters",
            "public_instance", "public_instance_sha256", "public_matrix_binding_hex",
            "oracle_signature_index",
            "message_sha256", "message_length", "sign_attempts", "abort_count",
            "root_case_count", "path_case_count", "error_zero_count", "error_one_count",
            "mathematical_payload_bits", "mathematical_payload_bytes_ceiling",
            "first_message_hash_hex", "signature",
        }
        signature_schema = envelope.get("schema")
        expected_top = recovery_top if signature_schema == "bittersweet-v1-full-l1-signature-reproduction-v1" else oracle_top
        if set(envelope) != expected_top:
            raise ValueError("signature envelope shape mismatch")
        if signature_schema not in {
            "bittersweet-v1-full-l1-signature-reproduction-v1",
            "bittersweet-v1-full-l1-oracle-signature-v1",
        }:
            raise ValueError("wrong signature schema")
        if envelope["target_pdf_sha256"] != PDF_SHA:
            raise ValueError("signature targets another PDF")
        if envelope["model_scope"] != MODEL_SCOPE:
            raise ValueError("wrong signature model scope")
        if envelope["parameters"] != SIGNATURE_PARAMETERS:
            raise ValueError("wrong signature parameters")
        if signature_schema == "bittersweet-v1-full-l1-signature-reproduction-v1":
            if public.get("schema") != "bittersweet-l1-public-interval-instance-v1":
                raise ValueError("recovery signature requires the public interval schema")
            if envelope["public_instance"] != "public-intervals.json":
                raise ValueError("wrong recovery public-instance label")
            if envelope["public_freeze"] != "candidate-commitment.json":
                raise ValueError("wrong candidate-commitment label")
            decode_hex(envelope["public_freeze_sha256"], 32, "candidate commitment digest")
            decode_hex(envelope["recovered_key_sha256"], 32, "recovered-key digest")
        else:
            if public.get("schema") != "bittersweet-v1-full-signature-public-key-v1":
                raise ValueError("oracle signature requires the full public-key schema")
            if envelope["public_instance"] != "public-key.json":
                raise ValueError("wrong oracle public-instance label")
            if type(envelope["oracle_signature_index"]) is not int or not 0 <= envelope[
                "oracle_signature_index"
            ] < 16:
                raise ValueError("bad oracle signature index")
        if (
            type(envelope["sign_attempts"]) is not int
            or type(envelope["abort_count"]) is not int
            or envelope["sign_attempts"] < 1
            or envelope["abort_count"] < 0
            or envelope["sign_attempts"] != envelope["abort_count"] + 1
        ):
            raise ValueError("bad signing-attempt metadata")
        public_sha = hashlib.sha256(public_raw).hexdigest()
        if envelope["public_instance_sha256"] != public_sha:
            raise ValueError("signature is not bound to supplied public instance")
        if envelope["message_sha256"] != hashlib.sha256(message).hexdigest() or envelope["message_length"] != len(message):
            raise ValueError("message metadata mismatch")
        matrix, public_y = parse_public(public)
        binding = bind_matrix(matrix)
        if envelope["public_matrix_binding_hex"] != binding.hex():
            raise ValueError("expanded-matrix binding mismatch")
        signature = envelope["signature"]
        if not isinstance(signature, dict) or set(signature) != {"salt_hex", "challenge", "responses"}:
            raise ValueError("signature body shape mismatch")
        salt = decode_hex(signature["salt_hex"], 16, "salt")
        challenge = signature["challenge"]
        if not isinstance(challenge, list) or len(challenge) != REPS or any(type(x) is not int or not 0 <= x < PARTIES for x in challenge):
            raise ValueError("bad challenge")
        responses = signature["responses"]
        if not isinstance(responses, list) or len(responses) != REPS:
            raise ValueError("bad response count")

        reconstructed_outputs: list[list[list[int]]] = []
        reconstructed_commits: list[list[bytes]] = []
        opened_key_hash = hashlib.sha256()
        error_ones = 0
        root_cases = 0
        observation_records: list[dict[str, Any]] = []
        bracket_lower = [0] * NROWS
        bracket_upper = [(1 << AB) - 1] * NROWS
        for repetition, (hidden, response) in enumerate(zip(challenge, responses)):
            if not isinstance(response, dict):
                raise ValueError("response is not an object")
            common = {"case", "hidden_commitment_hex", "errors_msb_packed_hex"}
            if hidden == PARTIES - 1:
                if set(response) != common | {"root_hex"} or response.get("case") != "root":
                    raise ValueError("root-case response shape mismatch")
                root = decode_hex(response["root_hex"], 16, "GGM root")
                leaf_map = expand_root(root)
                opened_keys = {i: share_from_leaf(leaf_map[i], i, repetition, salt) for i in range(PARTIES - 1)}
                root_cases += 1
            else:
                if set(response) != common | {"path_hex", "last_key_hex"} or response.get("case") != "path":
                    raise ValueError("path-case response shape mismatch")
                raw_path = response["path_hex"]
                if not isinstance(raw_path, list) or len(raw_path) != 5:
                    raise ValueError("bad path encoding")
                path = [decode_hex(x, 16, "GGM path seed") for x in raw_path]
                leaf_map = expand_copath(path, hidden)
                opened_keys = {
                    i: share_from_leaf(leaf_map[i], i, repetition, salt)
                    for i in range(PARTIES - 1)
                    if i != hidden
                }
                last = response["last_key_hex"]
                if not isinstance(last, list) or len(last) != NCOLS or any(not isinstance(x, str) or len(x) != 24 or x.lower() != x for x in last):
                    raise ValueError("bad correction-key encoding")
                opened_keys[PARTIES - 1] = [int(x, 16) for x in last]
            if set(opened_keys) != set(range(PARTIES)) - {hidden}:
                raise AssertionError("opened-key party set mismatch")
            errors = decode_errors(response["errors_msb_packed_hex"])
            error_ones += sum(errors)
            hidden_commitment = decode_hex(response["hidden_commitment_hex"], 32, "hidden commitment")

            outputs: list[list[int] | None] = [None] * PARTIES
            commitments: list[bytes | None] = [None] * PARTIES
            aggregate_key = [0] * NCOLS
            for party in sorted(opened_keys):
                key = opened_keys[party]
                if len(key) != NCOLS or any(type(x) is not int or not 0 <= x < MODQ for x in key):
                    raise ValueError("bad opened key")
                opened_key_hash.update(word(repetition, 2) + word(party, 2) + vector(key, 12))
                outputs[party] = rounded(multiply(matrix, key))
                commitments[party] = key_commitment(key, party, repetition, salt)
                aggregate_key = [(x + y) & MASKQ for x, y in zip(aggregate_key, key)]
            opened_product = multiply(matrix, aggregate_key)
            rounded_aggregate = rounded(opened_product)
            hidden_output = [(public_y[r] - rounded_aggregate[r] - errors[r]) % MODP for r in range(NROWS)]
            outputs[hidden] = hidden_output
            commitments[hidden] = hidden_commitment
            reconstructed = [(rounded_aggregate[r] + hidden_output[r]) % MODP for r in range(NROWS)]
            difference = [(public_y[r] - reconstructed[r]) % MODP for r in range(NROWS)]
            if difference != errors or any(x not in (0, 1) for x in difference):
                raise ValueError("Figure 3 modular error predicate failed")
            if any(x is None for x in outputs) or any(x is None for x in commitments):
                raise AssertionError("incomplete first-message reconstruction")
            reconstructed_outputs.append([x for x in outputs if x is not None])
            reconstructed_commits.append([x for x in commitments if x is not None])
            if collect_observations:
                # These are exactly the verifier-visible quantities used by
                # the public interval attack.  The aggregate key is reconstructed from the
                # response; X*aggregate_key gives the opened sum S.  Its
                # middle slice A=S[3..93], together with the response error
                # bit, yields one strict bound on the fixed secret buffer B.
                thresholds = [(value >> 3) & ((1 << AB) - 1) for value in opened_product]
                for row, (threshold, error) in enumerate(zip(thresholds, errors)):
                    if error == 0:
                        bracket_lower[row] = max(bracket_lower[row], threshold + 1)
                    else:
                        bracket_upper[row] = min(bracket_upper[row], threshold - 1)
                observation_records.append(
                    {
                        "repetition": repetition,
                        "hidden_party": hidden,
                        "opened_key_sum_hex": [f"{x:024x}" for x in aggregate_key],
                        "errors_msb_packed_hex": response["errors_msb_packed_hex"],
                    }
                )

        digest_value = hash_first_message(reconstructed_outputs, reconstructed_commits, message, binding, public_y, salt)
        derived = derive_challenge(digest_value)
        if envelope["first_message_hash_hex"] != digest_value.hex():
            raise ValueError("recorded first-message hash mismatch")
        if challenge != derived:
            raise ValueError("Fiat--Shamir challenge mismatch")
        if envelope["root_case_count"] != root_cases or envelope["path_case_count"] != REPS - root_cases:
            raise ValueError("case-count metadata mismatch")
        if envelope["error_one_count"] != error_ones or envelope["error_zero_count"] != REPS * NROWS - error_ones:
            raise ValueError("error-count metadata mismatch")
        payload_bits = 128 + 130
        for hidden in challenge:
            payload_bits += NROWS + 8 * 32
            payload_bits += 8 * 16 if hidden == PARTIES - 1 else 5 * 8 * 16 + NCOLS * QB
        if (
            envelope["mathematical_payload_bits"] != payload_bits
            or envelope["mathematical_payload_bytes_ceiling"] != (payload_bits + 7) // 8
        ):
            raise ValueError("payload-size metadata mismatch")
        outcome.update(
            {
                "accepted": True,
                "reason": "accepted",
                "derived_challenge": derived,
                "first_message_hash_hex": digest_value.hex(),
                "opened_keys_sha256": opened_key_hash.hexdigest(),
                "root_case_count": root_cases,
                "path_case_count": REPS - root_cases,
                "error_zero_count": REPS * NROWS - error_ones,
                "error_one_count": error_ones,
                "repetitions_verified": REPS,
                "rows_per_repetition": NROWS,
            }
        )
        if collect_observations:
            bracket_rows = []
            for row, (lo, hi, y) in enumerate(zip(bracket_lower, bracket_upper, public_y)):
                bracket_rows.append(
                    {
                        "row": row,
                        "buffer_lower_inclusive": lo,
                        "buffer_upper_inclusive": hi,
                        "product_lower_inclusive": (y << 93) + 8 * lo,
                        "product_upper_inclusive": (y << 93) + 8 * (hi + 1) - 1,
                        "public_y": y,
                    }
                )
            outcome["_oracle_observations"] = {
                "schema": "bittersweet-v1-public-signature-observations-v1",
                "scope": "Public projection from one accepted full optimized signature; no key or private truth consumed.",
                "mapping": "For S=X*sum(opened keys) mod 2^96, A=S[3..93]. Error 0 gives B>=A+1; error 1 gives B<=A-1.",
                "parameters": {
                    "q": QB,
                    "p_prime": PB,
                    "alpha": AB,
                    "p": P_BITS,
                    "n": NCOLS,
                    "m": NROWS,
                    "d": PARTIES,
                    "t": REPS,
                },
                "accepted_signature_count": 1,
                "comparisons_per_row": REPS,
                "repetitions": observation_records,
                "derived_bracket_rows": bracket_rows,
                "private_truth_read": False,
            }
        return outcome
    except (AssertionError, KeyError, TypeError, ValueError) as exc:
        outcome["reason"] = f"{type(exc).__name__}: {exc}"
        return outcome


def mutation_controls(public: dict[str, Any], public_raw: bytes, message: bytes, envelope: dict[str, Any]) -> dict[str, Any]:
    controls: dict[str, dict[str, Any]] = {}

    def record(name: str, p: dict[str, Any], raw: bytes, msg: bytes, sig: dict[str, Any]) -> None:
        result = verify(p, raw, msg, sig)
        controls[name] = {"rejected": not result["accepted"], "reason": result["reason"]}

    # Refresh envelope metadata so this control reaches the Fiat--Shamir
    # transcript check instead of stopping at the noncryptographic length/hash
    # fields.
    changed_message = message + b"\x00changed"
    mutated = copy.deepcopy(envelope)
    mutated["message_sha256"] = hashlib.sha256(changed_message).hexdigest()
    mutated["message_length"] = len(changed_message)
    record("changed_message", public, public_raw, changed_message, mutated)

    mutated = copy.deepcopy(envelope)
    packed = bytearray.fromhex(mutated["signature"]["responses"][0]["errors_msb_packed_hex"])
    packed[0] ^= 0x80
    mutated["signature"]["responses"][0]["errors_msb_packed_hex"] = packed.hex()
    record("flipped_error_bit", public, public_raw, message, mutated)

    mutated = copy.deepcopy(envelope)
    commitment = bytearray.fromhex(mutated["signature"]["responses"][0]["hidden_commitment_hex"])
    commitment[0] ^= 1
    mutated["signature"]["responses"][0]["hidden_commitment_hex"] = commitment.hex()
    record("flipped_hidden_commitment", public, public_raw, message, mutated)

    mutated = copy.deepcopy(envelope)
    salt = bytearray.fromhex(mutated["signature"]["salt_hex"])
    salt[0] ^= 1
    mutated["signature"]["salt_hex"] = salt.hex()
    record("flipped_salt", public, public_raw, message, mutated)

    mutated = copy.deepcopy(envelope)
    mutated["signature"]["challenge"][0] = (mutated["signature"]["challenge"][0] + 1) % PARTIES
    record("changed_challenge_index", public, public_raw, message, mutated)

    responses = envelope["signature"]["responses"]
    root_index = next((i for i, response in enumerate(responses) if response["case"] == "root"), None)
    if root_index is not None:
        mutated = copy.deepcopy(envelope)
        root = bytearray.fromhex(mutated["signature"]["responses"][root_index]["root_hex"])
        root[0] ^= 1
        mutated["signature"]["responses"][root_index]["root_hex"] = root.hex()
        record("flipped_ggm_root", public, public_raw, message, mutated)
    path_index = next((i for i, response in enumerate(responses) if response["case"] == "path"), None)
    if path_index is not None:
        mutated = copy.deepcopy(envelope)
        node = bytearray.fromhex(mutated["signature"]["responses"][path_index]["path_hex"][0])
        node[0] ^= 1
        mutated["signature"]["responses"][path_index]["path_hex"][0] = node.hex()
        record("flipped_ggm_path", public, public_raw, message, mutated)

        mutated = copy.deepcopy(envelope)
        value = int(mutated["signature"]["responses"][path_index]["last_key_hex"][0], 16) ^ 1
        mutated["signature"]["responses"][path_index]["last_key_hex"][0] = f"{value:024x}"
        record("flipped_correction_key", public, public_raw, message, mutated)

    mutated = copy.deepcopy(envelope)
    padded = bytearray.fromhex(mutated["signature"]["responses"][0]["errors_msb_packed_hex"])
    padded[-1] |= 0x1F
    mutated["signature"]["responses"][0]["errors_msb_packed_hex"] = padded.hex()
    record("nonzero_error_padding_mask_0x1f", public, public_raw, message, mutated)

    mutated_public = copy.deepcopy(public)
    if mutated_public.get("schema") == "bittersweet-l1-public-interval-instance-v1":
        mutated_public["rows"][0]["public_y"] = (int(mutated_public["rows"][0]["public_y"]) + 1) % MODP
    else:
        mutated_public["public_y"][0] = (int(mutated_public["public_y"][0]) + 1) % MODP
    mutated_raw = (json.dumps(mutated_public, indent=2, sort_keys=True) + "\n").encode()
    record("changed_public_y", mutated_public, mutated_raw, message, envelope)

    mutated_public = copy.deepcopy(public)
    mutated_public["matrix_X_hex"][0][0] = f"{(int(mutated_public['matrix_X_hex'][0][0], 16) ^ 1):024x}"
    mutated_raw = (json.dumps(mutated_public, indent=2, sort_keys=True) + "\n").encode()
    record("changed_public_matrix", mutated_public, mutated_raw, message, envelope)

    return {
        "status": "PASS" if controls and all(x["rejected"] for x in controls.values()) else "FAIL",
        "controls": controls,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--public-instance", required=True)
    ap.add_argument("--signature", required=True)
    ap.add_argument("--message-hex", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--observations-output")
    ap.add_argument("--skip-mutation-controls", action="store_true")
    args = ap.parse_args()
    public_path, signature_path = pathlib.Path(args.public_instance), pathlib.Path(args.signature)
    public_raw, signature_raw = public_path.read_bytes(), signature_path.read_bytes()
    public, envelope = json.loads(public_raw), json.loads(signature_raw)
    message = bytes.fromhex(args.message_hex)
    baseline = verify(public, public_raw, message, envelope, collect_observations=True)
    observations = baseline.pop("_oracle_observations", None)
    controls = (
        mutation_controls(public, public_raw, message, envelope)
        if baseline["accepted"] and not args.skip_mutation_controls
        else {"status": "SKIPPED" if baseline["accepted"] else "NOT_RUN", "controls": {}}
    )
    result = {
        "experiment": "BTS-PUBLIC-STRICT-VERIFIER-V1",
        "status": "FULL_L1_SIGNATURE_ACCEPTED"
        if baseline["accepted"] and controls["status"] in {"PASS", "SKIPPED"}
        else "VERIFICATION_FAILED",
        "target_pdf_sha256": PDF_SHA,
        "public_instance": str(public_path),
        "public_instance_sha256": hashlib.sha256(public_raw).hexdigest(),
        "signature_artifact": str(signature_path),
        "signature_artifact_sha256": hashlib.sha256(signature_raw).hexdigest(),
        "message_sha256": hashlib.sha256(message).hexdigest(),
        "message_length": len(message),
        "verifier_source_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
        "private_truth_read": False,
        "baseline": baseline,
        "negative_controls": controls,
    }
    if observations is not None and args.observations_output:
        observations.update(
            {
                "public_instance_sha256": hashlib.sha256(public_raw).hexdigest(),
                "signature_artifact_sha256": hashlib.sha256(signature_raw).hexdigest(),
                "message_sha256": hashlib.sha256(message).hexdigest(),
                "extractor_verifier_source_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
            }
        )
        observations_path = pathlib.Path(args.observations_output)
        observations_path.parent.mkdir(parents=True, exist_ok=True)
        observations_path.write_bytes((json.dumps(observations, indent=2, sort_keys=True) + "\n").encode())
        result["public_observations_artifact"] = str(observations_path)
        result["public_observations_artifact_sha256"] = hashlib.sha256(observations_path.read_bytes()).hexdigest()
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes((json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["status"] != "FULL_L1_SIGNATURE_ACCEPTED":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
