#!/usr/bin/env python3
"""Independent typed-paper replay candidate for ePrint 2024/649.

DEVELOPMENT STATUS: prospectively sealed, not executed.

This is a source-independent mathematical model.  It deliberately does not
implement LowMC, M-FORS secret paths, MPC-in-the-Head, an author codec, or the
partial HBGS source tree.  Credential issuance and the two proof systems are
ideal, stateful capabilities.  The ordinary paper GSig/GVf/Trace/TVf data flow
and the Appendix-E.2 one-/two-block H1 formulas are represented explicitly.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import struct
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

try:
    import resource
except ImportError:  # pragma: no cover - retained for non-Unix review hosts
    resource = None


PROFILE_ID = (
    "SITH-2024-649-HBGS-TEST2-N255-Q1024-H1-D16-K70-"
    "NR1120-NU70-Q128-G2P10-PAPER-ALG2-ZEROPAD"
)
PAPER_SHA256 = "67581ad5d1ae2455573cdb9b043344d91ca04788797318a7906ed500380a9881"
CANDIDATE_ID = "sphinx-independent-typed-paper-v2"


class ModelFailure(RuntimeError):
    """Raised only for a violated model invariant."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ModelFailure(message)


def _mask(width: int) -> int:
    return (1 << width) - 1 if width else 0


@dataclass(frozen=True)
class Bits:
    """A finite bit string whose length remains part of its value and type."""

    width: int
    value: int

    def __post_init__(self) -> None:
        if self.width < 0:
            raise ValueError("negative bit-string width")
        if self.value < 0 or self.value > _mask(self.width):
            raise ValueError("bit-string value does not fit declared width")

    @classmethod
    def zero(cls, width: int) -> "Bits":
        return cls(width, 0)

    @classmethod
    def random(cls, width: int) -> "Bits":
        # This samples the entire domain.  In particular, zero is not rejected.
        return cls(width, secrets.randbits(width))

    def to_bytes(self) -> bytes:
        return self.value.to_bytes((self.width + 7) // 8, "big")

    def encoded(self) -> bytes:
        return b"B" + _u64(self.width) + _frame(self.to_bytes())

    def concat(self, *others: "Bits") -> "Bits":
        width = self.width
        value = self.value
        for other in others:
            value = (value << other.width) | other.value
            width += other.width
        return Bits(width, value)

    def split(self, widths: Iterable[int]) -> tuple["Bits", ...]:
        requested = tuple(widths)
        if any(width < 0 for width in requested) or sum(requested) != self.width:
            raise ValueError("invalid split widths")
        remaining = self.width
        answer: list[Bits] = []
        for width in requested:
            remaining -= width
            answer.append(Bits(width, (self.value >> remaining) & _mask(width)))
        return tuple(answer)

    def xor(self, other: "Bits") -> "Bits":
        if self.width != other.width:
            raise ValueError("xor width mismatch")
        return Bits(self.width, self.value ^ other.value)

    def flip_low_bit(self) -> "Bits":
        if self.width == 0:
            raise ValueError("cannot mutate an empty bit string")
        return Bits(self.width, self.value ^ 1)


def _u64(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative framed integer")
    return struct.pack(">Q", value)


def _frame(payload: bytes) -> bytes:
    return _u64(len(payload)) + payload


def _encode_atom(value: Any) -> bytes:
    if isinstance(value, Bits):
        return value.encoded()
    if isinstance(value, bytes):
        return b"Y" + _frame(value)
    if isinstance(value, str):
        return b"S" + _frame(value.encode("utf-8"))
    if isinstance(value, int):
        return b"I" + _u64(value)
    if isinstance(value, (tuple, list)):
        return b"L" + _u64(len(value)) + b"".join(
            _frame(_encode_atom(item)) for item in value
        )
    raise TypeError(f"unsupported framed value: {type(value)!r}")


def _digest_bits(domain: str, *items: Any, width: int) -> Bits:
    transcript = hashlib.shake_256()
    transcript.update(_frame(_encode_atom(domain)))
    for item in items:
        transcript.update(_frame(_encode_atom(item)))
    raw = transcript.digest((width + 7) // 8)
    return Bits(width, int.from_bytes(raw, "big") & _mask(width))


def _tag(secret: bytes, domain: str, payload: bytes) -> bytes:
    return hmac.new(secret, _frame(domain.encode("ascii")) + payload, hashlib.sha256).digest()


def _fingerprint(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class Parameters:
    n: int = 255
    q: int = 1024
    h: int = 1
    d: int = 16
    k: int = 70
    nr: int = 1120
    nu: int = 70
    quantum_security_bits: int = 128
    mpc_parties: int = 16
    partial_path_repetitions: int = 16

    @property
    def gp(self) -> tuple[int, int, int, int, int]:
        return (self.n, self.q, self.h, self.d, self.k)

    @property
    def index_bits(self) -> int:
        return (self.q - 1).bit_length() * self.h

    @property
    def mfors_public_key_bits(self) -> int:
        return self.d * self.k

    @property
    def top_height(self) -> int:
        return (self.k - 1).bit_length()

    @property
    def top_capacity(self) -> int:
        return 1 << self.top_height

    def validate(self) -> None:
        require(self.gp == (255, 1024, 1, 16, 70), "profile gp mismatch")
        require((self.nr, self.nu) == (1120, 70), "profile MPC-count mismatch")
        require(self.index_bits == 10, "profile index width mismatch")
        require(self.mfors_public_key_bits == 1120, "profile M-FORS width mismatch")
        require(self.top_height == 7, "profile top-tree height mismatch")
        require(self.top_capacity - self.k == 58, "profile padding count mismatch")
        require(self.nr == self.partial_path_repetitions * self.k, "round schedule mismatch")

    def evidence(self) -> dict[str, Any]:
        return {
            "profile_id": PROFILE_ID,
            "n": self.n,
            "q": self.q,
            "h": self.h,
            "d": self.d,
            "k": self.k,
            "gp": list(self.gp),
            "NR": self.nr,
            "NU": self.nu,
            "claimed_quantum_security_bits": self.quantum_security_bits,
            "mfors_public_key_bits_d_times_k": self.mfors_public_key_bits,
            "mfors_base_tree_count": self.k,
            "mfors_base_tree_logical_leaves_each": 1 << self.d,
            "top_tree_height": self.top_height,
            "top_tree_capacity": self.top_capacity,
            "top_tree_zero_leaves": self.top_capacity - self.k,
            "mpc_parties": self.mpc_parties,
            "partial_path_repetitions": self.partial_path_repetitions,
        }


@dataclass(frozen=True)
class PaddingAudit:
    algorithm: str
    initial_leaf_count: int
    capacity: int
    appended_zero_leaf_count: int
    zero_leaf_width_bits: int
    height: int
    lifted_node_count: int
    root_width_bits: int


class IdealPrimitives:
    """Typed ideal surrogates; none is an author-byte implementation."""

    def __init__(self, parameters: Parameters):
        parameters.validate()
        self.p = parameters

    def lowmc_surrogate(self, key: Bits, plaintext: Bits) -> Bits:
        require(key.width == self.p.n, "LowMC-surrogate key width")
        require(plaintext.width == self.p.n, "LowMC-surrogate block width")
        return _digest_bits(
            "SITH/ideal-lowmc-surrogate/not-author-code/v1",
            key,
            plaintext,
            width=self.p.n,
        )

    def h1(self, value: Bits) -> Bits:
        n = self.p.n
        if value.width == n:
            # Appendix E.2: hash_1(u) = low_mc(u, 0^n).
            return self.lowmc_surrogate(value, Bits.zero(n))
        if value.width == 2 * n:
            u, v = value.split((n, n))
            # Appendix E.2: hash_1a(u,v) = low_mc(u,v) xor v.
            return self.lowmc_surrogate(u, v).xor(v)
        if value.width == 3 * n:
            u, v, w = value.split((n, n, n))
            # Appendix E.2: hash_1b(u,v,w) = low_mc(hash_1a(u,v),w) xor w.
            return self.lowmc_surrogate(self.h1(u.concat(v)), w).xor(w)
        # The paper gives H1 the abstract {0,1}* domain but no general LowMC
        # framing.  This explicit ideal fallback is non-normative and the
        # result under test does not rely on a collision or equality here.
        return _digest_bits(
            "SITH/ideal-H1-general/explicitly-nonnormative/v1",
            value,
            width=n,
        )

    def f(self, key: Bits, value: Bits) -> Bits:
        require(key.width == self.p.n and value.width == self.p.n, "F width mismatch")
        return _digest_bits("SITH/ideal-F-PRF/v1", key, value, width=self.p.n)

    def h3(self, value: Bits) -> Bits:
        return _digest_bits(
            "SITH/ideal-H3/v1",
            value,
            width=self.p.mfors_public_key_bits + self.p.index_bits,
        )

    def algorithm2_top_root(
        self, aux: bytes, base_roots: tuple[Bits, ...]
    ) -> tuple[Bits, PaddingAudit]:
        require(len(base_roots) == self.p.k, "Algorithm-2 root count")
        require(all(root.width == self.p.n for root in base_roots), "Algorithm-2 root width")
        zero_leaf = Bits.zero(self.p.n)
        appended = self.p.top_capacity - len(base_roots)
        layer = list(base_roots) + [zero_leaf for _ in range(appended)]
        require(len(layer) == self.p.top_capacity, "Algorithm-2 capacity")

        # This is the complete binary-tree loop from Algorithm 2.  There is
        # intentionally no odd-node/copy/lift branch from Appendix E.5.
        for level in range(self.p.top_height - 1, 0, -1):
            parent_count = 1 << level
            require(len(layer) == 2 * parent_count, "Algorithm-2 layer shape")
            layer = [
                _digest_bits(
                    "SITH/Algorithm2/top-internal-H1/typed/v1",
                    aux,
                    self.p.k,
                    level,
                    index,
                    layer[2 * index],
                    layer[2 * index + 1],
                    width=self.p.n,
                )
                for index in range(parent_count)
            ]

        require(len(layer) == 2, "Algorithm-2 pre-root shape")
        root = _digest_bits(
            "SITH/Algorithm2/top-root-H2/typed/v1",
            aux,
            self.p.k,
            0,
            0,
            layer[0],
            layer[1],
            width=self.p.mfors_public_key_bits,
        )
        audit = PaddingAudit(
            algorithm="Appendix-B Algorithm-2 zero padding",
            initial_leaf_count=self.p.k,
            capacity=self.p.top_capacity,
            appended_zero_leaf_count=appended,
            zero_leaf_width_bits=self.p.n,
            height=self.p.top_height,
            lifted_node_count=0,
            root_width_bits=self.p.mfors_public_key_bits,
        )
        return root, audit

    def ideal_mfors_public_key(self, hidden_seed: bytes, aux: bytes) -> tuple[Bits, PaddingAudit]:
        # Base-tree roots are abstract outputs.  Only the normative Algorithm-2
        # top-tree shape and zero padding are expanded in this candidate.
        roots = tuple(
            _digest_bits(
                "SITH/ideal-MFORS-base-root/v1",
                hidden_seed,
                aux,
                index,
                width=self.p.n,
            )
            for index in range(self.p.k)
        )
        return self.algorithm2_top_root(aux, roots)


class PaperSidPolicy:
    name = "paper-unframed-H1(msg||str)"

    @staticmethod
    def sid(primitives: IdealPrimitives, message: Bits, string: Bits) -> Bits:
        require(string.width == primitives.p.n, "str width mismatch")
        return primitives.h1(message.concat(string))


class FramedSidPolicy:
    name = "counterfactual-length-framed-domain-separated-H1(msg,str)"

    @staticmethod
    def sid(primitives: IdealPrimitives, message: Bits, string: Bits) -> Bits:
        require(string.width == primitives.p.n, "str width mismatch")
        # _digest_bits frames each typed argument, including both bit lengths.
        return _digest_bits(
            "SITH/counterfactual/framed-domain-separated-sid/v1",
            message,
            string,
            width=primitives.p.n,
        )


@dataclass(frozen=True)
class Credential:
    serial: bytes
    seal: bytes


@dataclass(frozen=True)
class CredentialRecord:
    serial: bytes
    member_id: Bits
    entry_token: Bits
    membership_ticket: Bits
    leaf_index: int
    leaf_public_key: Bits
    root_public_key: Bits
    padding_audit: PaddingAudit


@dataclass(frozen=True)
class MemberKey:
    tracing_key: Bits
    signing_key: Bits
    credential_randomizer: Bits
    credential: Credential


class CredentialAuthority:
    """Ideal issuance capability; public data cannot mint a credential."""

    def __init__(self, primitives: IdealPrimitives):
        self.primitives = primitives
        self._seal_key = secrets.token_bytes(32)
        self._records: dict[bytes, CredentialRecord] = {}

    @staticmethod
    def _record_bytes(record: CredentialRecord) -> bytes:
        return _encode_atom(
            (
                record.serial,
                record.member_id,
                record.entry_token,
                record.membership_ticket,
                record.leaf_index,
                record.leaf_public_key,
                record.root_public_key,
                asdict(record.padding_audit).__repr__(),
            )
        )

    def issue(
        self,
        tracing_key: Bits,
        signing_key: Bits,
        credential_randomizer: Bits,
        gid: Bits,
        root_public_key: Bits,
    ) -> tuple[Credential, CredentialRecord]:
        while True:
            serial = b"CRED" + secrets.token_bytes(28)
            if serial not in self._records:
                break
        member_id = self.primitives.f(tracing_key, gid)
        entry_token = self.primitives.f(signing_key, member_id)
        ticket_and_index = self.primitives.h3(entry_token.concat(credential_randomizer))
        membership_ticket, index_bits = ticket_and_index.split(
            (self.primitives.p.mfors_public_key_bits, self.primitives.p.index_bits)
        )
        leaf_seed = _tag(self._seal_key, "SITH/ideal-issued-leaf-seed/v1", serial)
        leaf_public_key, padding_audit = self.primitives.ideal_mfors_public_key(
            leaf_seed,
            _encode_atom(("issued-leaf", serial, index_bits.value)),
        )
        record = CredentialRecord(
            serial=serial,
            member_id=member_id,
            entry_token=entry_token,
            membership_ticket=membership_ticket,
            leaf_index=index_bits.value,
            leaf_public_key=leaf_public_key,
            root_public_key=root_public_key,
            padding_audit=padding_audit,
        )
        seal = _tag(self._seal_key, "SITH/ideal-credential-seal/v1", self._record_bytes(record))
        self._records[serial] = record
        return Credential(serial, seal), record

    def recognized(self, credential: Credential) -> bool:
        record = self._records.get(credential.serial)
        if record is None:
            return False
        expected = _tag(
            self._seal_key,
            "SITH/ideal-credential-seal/v1",
            self._record_bytes(record),
        )
        return len(credential.seal) == len(expected) and hmac.compare_digest(
            credential.seal, expected
        )

    def validate_witness(
        self,
        member: MemberKey,
        gid: Bits,
        root_public_key: Bits,
    ) -> Optional[CredentialRecord]:
        if not self.recognized(member.credential):
            return None
        record = self._records[member.credential.serial]
        member_id = self.primitives.f(member.tracing_key, gid)
        entry_token = self.primitives.f(member.signing_key, member_id)
        ticket_and_index = self.primitives.h3(
            entry_token.concat(member.credential_randomizer)
        )
        ticket, index_bits = ticket_and_index.split(
            (self.primitives.p.mfors_public_key_bits, self.primitives.p.index_bits)
        )
        checks = (
            record.member_id == member_id,
            record.entry_token == entry_token,
            record.membership_ticket == ticket,
            record.leaf_index == index_bits.value,
            record.root_public_key == root_public_key,
        )
        return record if all(checks) else None


@dataclass(frozen=True)
class GroupStatement:
    profile_id: str
    gp: tuple[int, int, int, int, int]
    root_public_key: Bits
    gid: Bits
    sid: Bits
    tracing_token: Bits
    commitment: Bits

    def encoded(self) -> bytes:
        return _encode_atom(
            (
                self.profile_id,
                self.gp,
                self.root_public_key,
                self.gid,
                self.sid,
                self.tracing_token,
                self.commitment,
            )
        )


@dataclass(frozen=True)
class GroupProof:
    nonce: bytes
    tag: bytes

    def encoded(self) -> bytes:
        return _encode_atom((self.nonce, self.tag))


class GroupProofService:
    """Ideal sound proof capability bound to the printed public statement."""

    def __init__(
        self,
        primitives: IdealPrimitives,
        authority: CredentialAuthority,
        root_public_key: Bits,
    ):
        self.primitives = primitives
        self.authority = authority
        self.root_public_key = root_public_key
        self._proof_key = secrets.token_bytes(32)

    def prove(self, member: MemberKey, statement: GroupStatement) -> GroupProof:
        p = self.primitives.p
        require(statement.profile_id == PROFILE_ID and statement.gp == p.gp, "proof profile")
        expected_gid = self.primitives.h1(self.root_public_key)
        require(statement.root_public_key == self.root_public_key, "proof rpk")
        require(statement.gid == expected_gid, "proof gid")
        record = self.authority.validate_witness(member, expected_gid, self.root_public_key)
        require(record is not None, "unissued or invalid credential")
        expected_stt = self.primitives.f(member.tracing_key, statement.sid)
        sst = self.primitives.f(member.signing_key, statement.sid)
        expected_com = self.primitives.h1(
            sst.concat(record.leaf_public_key, self.root_public_key)
        )
        require(statement.tracing_token == expected_stt, "proof stt relation")
        require(statement.commitment == expected_com, "proof com relation")
        nonce = b"GPROOF1" + secrets.token_bytes(25)
        proof_tag = _tag(
            self._proof_key,
            "SITH/ideal-group-proof/v1",
            statement.encoded() + _frame(nonce),
        )
        return GroupProof(nonce, proof_tag)

    def verify(self, statement: GroupStatement, proof: GroupProof) -> bool:
        if len(proof.nonce) != 32 or len(proof.tag) != 32:
            return False
        expected = _tag(
            self._proof_key,
            "SITH/ideal-group-proof/v1",
            statement.encoded() + _frame(proof.nonce),
        )
        return hmac.compare_digest(proof.tag, expected)


@dataclass(frozen=True)
class TraceStatement:
    member_id: Bits
    gid: Bits
    tracing_token: Bits
    sid: Bits

    def encoded(self) -> bytes:
        return _encode_atom((self.member_id, self.gid, self.tracing_token, self.sid))


@dataclass(frozen=True)
class TraceProof:
    nonce: bytes
    tag: bytes

    def encoded(self) -> bytes:
        return _encode_atom((self.nonce, self.tag))


class TraceProofService:
    """Ideal proof for id=F(tk,gid) and stt=F(tk,sid)."""

    def __init__(self, primitives: IdealPrimitives):
        self.primitives = primitives
        self._proof_key = secrets.token_bytes(32)

    def prove(self, tracing_key: Bits, statement: TraceStatement) -> TraceProof:
        require(
            self.primitives.f(tracing_key, statement.gid) == statement.member_id,
            "trace id relation",
        )
        require(
            self.primitives.f(tracing_key, statement.sid) == statement.tracing_token,
            "trace token relation",
        )
        nonce = b"TPROOF1" + secrets.token_bytes(25)
        proof_tag = _tag(
            self._proof_key,
            "SITH/ideal-trace-proof/v1",
            statement.encoded() + _frame(nonce),
        )
        return TraceProof(nonce, proof_tag)

    def verify(self, statement: TraceStatement, proof: TraceProof) -> bool:
        if len(proof.nonce) != 32 or len(proof.tag) != 32:
            return False
        expected = _tag(
            self._proof_key,
            "SITH/ideal-trace-proof/v1",
            statement.encoded() + _frame(proof.nonce),
        )
        return hmac.compare_digest(proof.tag, expected)


@dataclass(frozen=True)
class GroupSignature:
    string: Bits
    tracing_token: Bits
    commitment: Bits
    group_proof: GroupProof

    def encoded(self) -> bytes:
        return _encode_atom(
            (self.string, self.tracing_token, self.commitment, self.group_proof.encoded())
        )


@dataclass(frozen=True)
class RevocationList:
    epoch: int
    tracing_keys: tuple[Bits, ...]


@dataclass(frozen=True)
class TraceResult:
    member_id: Bits
    proof: TraceProof


@dataclass(frozen=True)
class TracerRecord:
    member_id: Bits
    tracing_key: Bits


@dataclass(frozen=True)
class PublicView:
    profile_id: str
    gp: tuple[int, int, int, int, int]
    root_public_key: Bits
    gid: Bits
    sid_policy: str
    credential_model: str
    proof_model: str


@dataclass(frozen=True)
class JoinPublicView:
    member_id: Bits
    accepted: bool
    credential_status: str


class GroupSystem:
    """Ordinary typed Join/GSig/GVf/Trace/TVf algorithms."""

    def __init__(self, parameters: Parameters, sid_policy: Any):
        parameters.validate()
        self.p = parameters
        self.primitives = IdealPrimitives(parameters)
        self.sid_policy = sid_policy
        root_seed = secrets.token_bytes(32)
        self.root_public_key, self.root_padding_audit = (
            self.primitives.ideal_mfors_public_key(root_seed, b"hyper-tree-root-(0,0)")
        )
        self.authority = CredentialAuthority(self.primitives)
        self.group_proofs = GroupProofService(
            self.primitives, self.authority, self.root_public_key
        )
        self.trace_proofs = TraceProofService(self.primitives)
        self._tracer_records: list[TracerRecord] = []

    @property
    def gid(self) -> Bits:
        return self.primitives.h1(self.root_public_key)

    def public_view(self) -> PublicView:
        return PublicView(
            profile_id=PROFILE_ID,
            gp=self.p.gp,
            root_public_key=self.root_public_key,
            gid=self.gid,
            sid_policy=self.sid_policy.name,
            credential_model="ideal issuance-gated opaque credential",
            proof_model="ideal sound statement-bound proof capabilities",
        )

    def join_honest(self) -> tuple[MemberKey, CredentialRecord, JoinPublicView]:
        tracing_key = Bits.random(self.p.n)
        signing_key = Bits.random(self.p.n)
        credential_randomizer = Bits.random(self.p.n)
        credential, record = self.authority.issue(
            tracing_key,
            signing_key,
            credential_randomizer,
            self.gid,
            self.root_public_key,
        )
        member = MemberKey(
            tracing_key=tracing_key,
            signing_key=signing_key,
            credential_randomizer=credential_randomizer,
            credential=credential,
        )
        self._tracer_records.append(TracerRecord(record.member_id, tracing_key))
        return member, record, JoinPublicView(record.member_id, True, "issuer-accepted")

    def sid(self, message: Bits, string: Bits) -> Bits:
        return self.sid_policy.sid(self.primitives, message, string)

    def group_statement(self, message: Bits, signature: GroupSignature) -> GroupStatement:
        sid = self.sid(message, signature.string)
        return GroupStatement(
            profile_id=PROFILE_ID,
            gp=self.p.gp,
            root_public_key=self.root_public_key,
            gid=self.gid,
            sid=sid,
            tracing_token=signature.tracing_token,
            commitment=signature.commitment,
        )

    def gsig(self, member: MemberKey, message: Bits) -> GroupSignature:
        # Ordinary signing samples every 255-bit string, including 0^255.
        string = Bits.random(self.p.n)
        sid = self.sid(message, string)
        record = self.authority.validate_witness(member, self.gid, self.root_public_key)
        require(record is not None, "GSig requires an issued credential")
        tracing_token = self.primitives.f(member.tracing_key, sid)
        signing_token = self.primitives.f(member.signing_key, sid)
        commitment = self.primitives.h1(
            signing_token.concat(record.leaf_public_key, self.root_public_key)
        )
        provisional = GroupSignature(
            string,
            tracing_token,
            commitment,
            GroupProof(b"", b""),
        )
        statement = self.group_statement(message, provisional)
        group_proof = self.group_proofs.prove(member, statement)
        return GroupSignature(string, tracing_token, commitment, group_proof)

    def gvf(self, message: Bits, signature: GroupSignature, revocations: RevocationList) -> bool:
        if signature.string.width != self.p.n or revocations.epoch < 0:
            return False
        sid = self.sid(message, signature.string)
        for tracing_key in revocations.tracing_keys:
            if tracing_key.width != self.p.n:
                return False
            if self.primitives.f(tracing_key, sid) == signature.tracing_token:
                return False
        return self.group_proofs.verify(self.group_statement(message, signature), signature.group_proof)

    def trace(self, message: Bits, signature: GroupSignature) -> Optional[TraceResult]:
        sid = self.sid(message, signature.string)
        for record in self._tracer_records:
            if self.primitives.f(record.tracing_key, sid) == signature.tracing_token:
                statement = TraceStatement(record.member_id, self.gid, signature.tracing_token, sid)
                return TraceResult(
                    record.member_id,
                    self.trace_proofs.prove(record.tracing_key, statement),
                )
        return None

    def tvf(
        self,
        member_id: Bits,
        proof: TraceProof,
        signature: GroupSignature,
        message: Bits,
    ) -> bool:
        statement = TraceStatement(
            member_id,
            self.gid,
            signature.tracing_token,
            self.sid(message, signature.string),
        )
        return self.trace_proofs.verify(statement, proof)

    def revocation_list_for(self, member_id: Bits, epoch: int) -> RevocationList:
        keys = tuple(
            record.tracing_key
            for record in self._tracer_records
            if record.member_id == member_id
        )
        require(len(keys) == 1, "revocation control member lookup")
        return RevocationList(epoch, keys)


@dataclass(frozen=True)
class Figure8Outcome:
    gvf_accepts: bool
    exact_pair_absent_from_s: bool
    message_fresh: bool
    tvf_accepts_for_id_h: bool
    figure8_returns_one: bool


class Figure8Game:
    """The complete Figure-8 endpoint and its three granted oracles."""

    def __init__(self, system: GroupSystem):
        self.system = system
        self.rl0 = RevocationList(0, tuple())
        self._member: Optional[MemberKey] = None
        self._credential_record: Optional[CredentialRecord] = None
        self.id_h: Optional[Bits] = None
        self.honest_log: list[tuple[Bits, GroupSignature]] = []
        self.query_counts = {"AddHU": 0, "GSigHU": 0, "TraceU": 0}

    @property
    def credential_record(self) -> CredentialRecord:
        require(self._credential_record is not None, "AddHU not completed")
        return self._credential_record

    def add_hu(self) -> JoinPublicView:
        self.query_counts["AddHU"] += 1
        require(self._member is None, "Figure 8 permits one honest user")
        member, record, public_view = self.system.join_honest()
        self._member = member
        self._credential_record = record
        self.id_h = record.member_id
        return public_view

    def gsig_hu(self, message: Bits) -> GroupSignature:
        self.query_counts["GSigHU"] += 1
        require(self._member is not None, "GSigHU requires AddHU")
        signature = self.system.gsig(self._member, message)
        self.honest_log.append((message, signature))
        return signature

    def trace_u(
        self,
        revocations: RevocationList,
        message: Bits,
        signature: GroupSignature,
    ) -> Optional[TraceResult]:
        self.query_counts["TraceU"] += 1
        if not self.system.gvf(message, signature, revocations):
            return None
        return self.system.trace(message, signature)

    def finish(
        self,
        message: Bits,
        signature: GroupSignature,
        trace_proof: TraceProof,
        tau: int,
    ) -> Figure8Outcome:
        require(self.id_h is not None, "Figure 8 requires AddHU")
        require(tau == 0, "this replay fixes tau=0 and RL_0")
        gvf_accepts = self.system.gvf(message, signature, self.rl0)
        pair_absent = all(
            not (message == logged_message and signature == logged_signature)
            for logged_message, logged_signature in self.honest_log
        )
        message_fresh = all(message != logged_message for logged_message, _ in self.honest_log)
        tvf_accepts = self.system.tvf(self.id_h, trace_proof, signature, message)
        return Figure8Outcome(
            gvf_accepts=gvf_accepts,
            exact_pair_absent_from_s=pair_absent,
            message_fresh=message_fresh,
            tvf_accepts_for_id_h=tvf_accepts,
            figure8_returns_one=gvf_accepts and pair_absent and tvf_accepts,
        )


def _fake_group_proof() -> GroupProof:
    return GroupProof(b"GPROOF0" + bytes(25), bytes(32))


def _fake_trace_proof() -> TraceProof:
    return TraceProof(b"TPROOF0" + bytes(25), bytes(32))


def _counterfactual_control(parameters: Parameters) -> dict[str, Any]:
    counterfactual = GroupSystem(parameters, FramedSidPolicy)
    member, _, _ = counterfactual.join_honest()
    epsilon = Bits.zero(0)
    original = counterfactual.gsig(member, epsilon)
    u = original.string
    transformed = GroupSignature(
        Bits.zero(parameters.n),
        original.tracing_token,
        original.commitment,
        original.group_proof,
    )
    rl0 = RevocationList(0, tuple())
    sid_original = counterfactual.sid(epsilon, u)
    sid_transformed = counterfactual.sid(u, transformed.string)
    original_accepts = counterfactual.gvf(epsilon, original, rl0)
    transformed_accepts = counterfactual.gvf(u, transformed, rl0)
    return {
        "policy": FramedSidPolicy.name,
        "separate_control_world": True,
        "ordinary_direct_signature_generations": 1,
        "figure8_GSigHU_queries": 0,
        "original_signature_accepts": original_accepts,
        "original_and_transformed_sid_differ": sid_original != sid_transformed,
        "transformed_signature_rejected": not transformed_accepts,
        "control_passes": (
            original_accepts and sid_original != sid_transformed and not transformed_accepts
        ),
    }


def _all_mapping_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            keys.add(str(key))
            keys.update(_all_mapping_keys(nested))
    elif isinstance(value, (list, tuple)):
        for nested in value:
            keys.update(_all_mapping_keys(nested))
    return keys


def run_trial(trial_number: int, parameters: Parameters) -> dict[str, Any]:
    started = time.perf_counter()
    system = GroupSystem(parameters, PaperSidPolicy)
    game = Figure8Game(system)
    epsilon = Bits.zero(0)

    # Control 1: public data and zero signing queries do not construct a valid
    # signature.  This is evaluated before AddHU and GSigHU.
    fake_signature = GroupSignature(
        Bits.zero(parameters.n),
        Bits.zero(parameters.n),
        Bits.zero(parameters.n),
        _fake_group_proof(),
    )
    zero_query_rejected = not system.gvf(epsilon, fake_signature, game.rl0)

    # Prepare Control 2 guesses now, but adjudicate them only after a genuine
    # credential and proof exist.  This avoids a vacuous empty-registry test.
    fake_credential = Credential(b"NO-CREDENTIAL".ljust(32, b"\x00"), bytes(32))

    join_view = game.add_hu()
    credential_synthesis_rejected = not system.authority.recognized(fake_credential)
    public_view_mapping = asdict(system.public_view())
    join_view_mapping = asdict(join_view)
    visible_keys = _all_mapping_keys((public_view_mapping, join_view_mapping))
    forbidden_secret_field_names = {
        "tracing_key",
        "signing_key",
        "credential_randomizer",
        "credential",
        "issuer_key",
        "seal_key",
        "proof_key",
        "member_key",
    }
    visible_secret_fields = sorted(visible_keys & forbidden_secret_field_names)

    # The sole honest-signature query in this Figure-8 trial.
    sigma_0 = game.gsig_hu(epsilon)
    original_accepts = system.gvf(epsilon, sigma_0, game.rl0)
    original_statement = system.group_statement(epsilon, sigma_0)
    proof_synthesis_rejected = not system.group_proofs.verify(
        original_statement, _fake_group_proof()
    )

    # Required transformation.  `u` is exactly the returned 255-bit str.
    u = sigma_0.string
    msg_star = u
    str_star = Bits.zero(parameters.n)
    sigma_star = GroupSignature(
        str_star,
        sigma_0.tracing_token,
        sigma_0.commitment,
        sigma_0.group_proof,
    )
    sid_0 = system.sid(epsilon, u)
    sid_star = system.sid(msg_star, str_star)
    appendix_e2_identity_holds = sid_0 == sid_star

    # The sole tracing query, with RL_0, supplies the game-required pi_t*.
    trace_result = game.trace_u(game.rl0, msg_star, sigma_star)
    trace_u_gate_accepts = trace_result is not None
    trace_identity_matches = bool(
        trace_result is not None and game.id_h is not None and trace_result.member_id == game.id_h
    )
    trace_proof = trace_result.proof if trace_result is not None else _fake_trace_proof()
    outcome = game.finish(msg_star, sigma_star, trace_proof, tau=0)

    # Control 3: pi_G is bound to the full printed public statement.
    changed_statement = GroupStatement(
        original_statement.profile_id,
        original_statement.gp,
        original_statement.root_public_key,
        original_statement.gid,
        original_statement.sid,
        original_statement.tracing_token.flip_low_bit(),
        original_statement.commitment,
    )
    changed_statement_reuse_rejected = not system.group_proofs.verify(
        changed_statement, sigma_0.group_proof
    )

    # Control 4: mutation of a signature field changes the ordinary statement.
    mutated_signature = GroupSignature(
        sigma_0.string,
        sigma_0.tracing_token,
        sigma_0.commitment.flip_low_bit(),
        sigma_0.group_proof,
    )
    signature_field_mutation_rejected = not system.gvf(
        epsilon, mutated_signature, game.rl0
    )

    # Control 5: replacing str by a fixed nonzero 255-bit value does not enact
    # the zero-extension identity and ordinary GVf rejects proof reuse.
    nonzero_string = Bits(parameters.n, 1)
    nonzero_replacement = GroupSignature(
        nonzero_string,
        sigma_star.tracing_token,
        sigma_star.commitment,
        sigma_star.group_proof,
    )
    nonzero_replacement_rejected = not system.gvf(
        msg_star, nonzero_replacement, game.rl0
    )

    # Control 6: the same transformed signature fails the paper revocation loop
    # when the hidden honest tracing key is present.  The key is never emitted.
    revoked = system.revocation_list_for(game.id_h, epoch=1)  # type: ignore[arg-type]
    revocation_rejected = not system.gvf(msg_star, sigma_star, revoked)

    # Control 7: a separately instantiated, ordinary framed-H1 world binds the
    # two typed operands and defeats the transformation.
    counterfactual = _counterfactual_control(parameters)

    retained_fields = {
        "tracing_token_stt": sigma_star.tracing_token == sigma_0.tracing_token,
        "commitment_com": sigma_star.commitment == sigma_0.commitment,
        "group_proof_pi_G": sigma_star.group_proof == sigma_0.group_proof,
    }
    exact_counts = game.query_counts == {"AddHU": 1, "GSigHU": 1, "TraceU": 1}
    padding_checks = [system.root_padding_audit, game.credential_record.padding_audit]
    padding_exact = all(
        audit.algorithm == "Appendix-B Algorithm-2 zero padding"
        and audit.initial_leaf_count == 70
        and audit.capacity == 128
        and audit.appended_zero_leaf_count == 58
        and audit.zero_leaf_width_bits == 255
        and audit.height == 7
        and audit.lifted_node_count == 0
        and audit.root_width_bits == 1120
        for audit in padding_checks
    )
    controls = {
        "public_only_zero_query_signature_construction_rejected": zero_query_rejected,
        "public_credential_synthesis_rejected": credential_synthesis_rejected,
        "public_proof_synthesis_rejected": proof_synthesis_rejected,
        "changed_statement_proof_reuse_rejected": changed_statement_reuse_rejected,
        "signature_field_mutation_rejected": signature_field_mutation_rejected,
        "nonzero_replacement_str_rejected": nonzero_replacement_rejected,
        "revocation_rejected": revocation_rejected,
        "framed_domain_separated_H1_counterfactual_rejected": counterfactual[
            "control_passes"
        ],
    }
    trial_success = all(
        (
            original_accepts,
            appendix_e2_identity_holds,
            trace_u_gate_accepts,
            trace_identity_matches,
            outcome.gvf_accepts,
            outcome.exact_pair_absent_from_s,
            outcome.message_fresh,
            outcome.tvf_accepts_for_id_h,
            outcome.figure8_returns_one,
            msg_star == u,
            str_star == Bits.zero(parameters.n),
            all(retained_fields.values()),
            exact_counts,
            padding_exact,
            not visible_secret_fields,
            all(controls.values()),
        )
    )

    return {
        "trial": trial_number,
        "success": trial_success,
        "profile_id": PROFILE_ID,
        "oracle_ledger": {
            **game.query_counts,
            "GSigHU_query_message": "epsilon (0-bit string)",
            "TraceU_revocation_epoch": 0,
            "honest_log_exact_pair_count": len(game.honest_log),
        },
        "transformation": {
            "returned_str_name": "u",
            "returned_str_width_bits": u.width,
            "returned_str_is_zero": u.value == 0,
            "fresh_msg_star_equals_u": msg_star == u,
            "fresh_msg_star_width_bits": msg_star.width,
            "replacement_str_star": "0^255",
            "replacement_str_star_is_zero": str_star == Bits.zero(parameters.n),
            "retained_fields": retained_fields,
            "H1_epsilon_concat_u_equals_H1_u": system.sid(epsilon, u) == system.primitives.h1(u),
            "H1_u_equals_H1_u_concat_zero255": appendix_e2_identity_holds,
            "original_and_transformed_sid_equal": sid_0 == sid_star,
        },
        "figure8_endpoint": {
            "tau": 0,
            "RL_tau": "RL_0",
            "TraceU_GVf_gate_accepts": trace_u_gate_accepts,
            "TraceU_returns_id_h": trace_identity_matches,
            "GVf_msg_star_sigma_star_RL0": outcome.gvf_accepts,
            "exact_pair_msg_star_sigma_star_absent_from_S": outcome.exact_pair_absent_from_s,
            "message_fresh_despite_not_required_by_exact_pair_game": outcome.message_fresh,
            "message_fresh_even_if_u_is_zero": outcome.message_fresh and msg_star.width == 255,
            "TVf_id_h_pi_t_star_sigma_star_msg_star": outcome.tvf_accepts_for_id_h,
            "Figure_8_returns_1": outcome.figure8_returns_one,
        },
        "controls": controls,
        "framed_counterfactual_detail": counterfactual,
        "credential_and_proof_boundary": {
            "credential_issuance_controlled": True,
            "proof_generation_requires_member_witness_and_issued_credential": True,
            "public_recomputation_interface_present": False,
            "attacker_view_top_level_fields": sorted(public_view_mapping.keys()),
            "join_view_top_level_fields": sorted(join_view_mapping.keys()),
            "member_or_authority_secret_fields_in_attacker_view": visible_secret_fields,
            "raw_secret_values_written_to_evidence": False,
            "runtime_secret_source": "Python secrets module / operating-system CSPRNG",
            "deterministic_seed_option": False,
        },
        "algorithm2_padding": {
            "all_primary_top_tree_builds_exact": padding_exact,
            "build_count": len(padding_checks),
            "builds": [asdict(audit) for audit in padding_checks],
            "appendix_E5_node_lifting_used": False,
        },
        "ordinary_api": {
            "GSig_and_GVf_share_sid_policy": PaperSidPolicy.name,
            "attack_only_verifier_branch": False,
            "original_signature_accepts": original_accepts,
            "str_sampler_conditions_away_zero": False,
        },
        "public_fingerprints_sha256": {
            "root_public_key": _fingerprint(system.root_public_key.encoded()),
            "original_signature": _fingerprint(sigma_0.encoded()),
            "transformed_signature": _fingerprint(sigma_star.encoded()),
        },
        "runtime_seconds": time.perf_counter() - started,
    }


def _machine_record() -> dict[str, Any]:
    version = sys.version_info
    record: dict[str, Any] = {
        "sys_platform": sys.platform,
        "os_name": os.name,
        "python_implementation": sys.implementation.name,
        "python_cache_tag": sys.implementation.cache_tag,
        "python_version": f"{version.major}.{version.minor}.{version.micro}",
        "python_releaselevel": version.releaselevel,
        "python_serial": version.serial,
        "logical_cpu_count": os.cpu_count(),
        "collection_method": "direct non-spawning sys/os primitives",
    }
    if hasattr(os, "uname"):
        uname = os.uname()
        record["os_uname"] = {
            "sysname": uname.sysname,
            "nodename": uname.nodename,
            "release": uname.release,
            "version": uname.version,
            "machine": uname.machine,
        }
    else:
        record["os_uname"] = None
    return record


def _peak_ram_record() -> dict[str, Any]:
    if resource is None:
        return {"value": None, "unit": "unavailable"}
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    unit = "KiB on Linux; bytes on macOS"
    return {"value": value, "unit": unit}


def build_evidence(trial_count: int, implementation_sha256: str) -> dict[str, Any]:
    parameters = Parameters()
    parameters.validate()
    run_started_utc = datetime.now(timezone.utc).isoformat()
    run_started = time.perf_counter()
    trials = [run_trial(index + 1, parameters) for index in range(trial_count)]
    successes = sum(1 for trial in trials if trial["success"])
    run_finished_utc = datetime.now(timezone.utc).isoformat()
    return {
        "schema_version": "1.0",
        "artifact_type": "independent_typed_paper_reproduction_evidence",
        "candidate_id": CANDIDATE_ID,
        "development_seal_status": "prospectively sealed before first execution",
        "paper": {
            "eprint": "2024/649",
            "sha256": PAPER_SHA256,
            "title": "Sphinx-in-the-Head: Group Signatures from Symmetric Primitives",
        },
        "profile": parameters.evidence(),
        "claim_scope": {
            "source_independent_typed_paper_model": True,
            "full_parameter_profile": True,
            "official_source_reproduction": False,
            "author_byte_conformance": False,
            "real_LowMC": False,
            "real_MFORS": False,
            "real_MPCitH": False,
            "ideal_credential_and_proof_abstraction": True,
            "primary_endpoint": "Figure 8 ExpNon-Frame with tau=0",
        },
        "implementation_sha256": implementation_sha256,
        "execution": {
            "started_utc": run_started_utc,
            "finished_utc": run_finished_utc,
            "runtime_seconds": time.perf_counter() - run_started,
            "peak_ram": _peak_ram_record(),
            "workers": 1,
            "machine": _machine_record(),
            "trials": trial_count,
            "successes": successes,
        },
        "aggregate_oracle_ledger": {
            "AddHU": sum(trial["oracle_ledger"]["AddHU"] for trial in trials),
            "GSigHU": sum(trial["oracle_ledger"]["GSigHU"] for trial in trials),
            "TraceU": sum(trial["oracle_ledger"]["TraceU"] for trial in trials),
            "per_trial_required_counts": {"AddHU": 1, "GSigHU": 1, "TraceU": 1},
            "per_trial_GSigHU_message": "epsilon",
            "per_trial_TraceU_list": "RL_0",
            "counterfactual_signatures_not_counted_as_game_queries": trial_count,
        },
        "all_trials_pass": successes == trial_count,
        "trials": trials,
    }


def _write_exclusive(path: Path, payload: bytes) -> None:
    if not path.parent.exists() or not path.parent.is_dir():
        raise FileNotFoundError("output parent directory must already exist")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the prospectively sealed independent typed-paper replay."
    )
    parser.add_argument(
        "--output",
        required=True,
        help="the one evidence JSON path; it must not already exist",
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=1,
        help="independent full games (default: 1; each uses one GSigHU query)",
    )
    args = parser.parse_args(argv)
    if args.trials < 1 or args.trials > 1000:
        parser.error("--trials must be between 1 and 1000")

    implementation_path = Path(__file__)
    implementation_sha256 = hashlib.sha256(implementation_path.read_bytes()).hexdigest()
    evidence = build_evidence(args.trials, implementation_sha256)
    serialized = (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode("utf-8")
    output_path = Path(args.output)
    _write_exclusive(output_path, serialized)
    print(
        "PASS" if evidence["all_trials_pass"] else "FAIL",
        f"trials={evidence['execution']['trials']}",
        f"successes={evidence['execution']['successes']}",
        f"evidence={output_path}",
    )
    return 0 if evidence["all_trials_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
