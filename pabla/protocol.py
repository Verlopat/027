"""Versioned, deterministic provenance primitives for PABLA.

This module is security-sensitive. Never silently coerce schema or signature failures.
A digest binds length-delimited bytes (not ambiguous concatenation).
"""
from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PROTOCOL = "PABLA-v1"
ZERO = "00" * 32
MAX_EVENT_BYTES = 1_048_576
MAX_BATCH = 10_000


class ProtocolError(ValueError):
    """Invalid protocol input or cryptographic evidence."""


def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out = {}
    for key, value in pairs:
        if key in out:
            raise ProtocolError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def loads_strict(data: str | bytes) -> Any:
    def reject_constant(x: str) -> None:
        raise ProtocolError(f"non-finite number: {x}")
    return json.loads(data, object_pairs_hook=unique_pairs, parse_constant=reject_constant)


def _check(value: Any, depth: int = 0) -> None:
    if depth > 30:
        raise ProtocolError("maximum JSON depth exceeded")
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > 2**53 - 1:
            raise ProtocolError("JSON integer outside interoperable safe range")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ProtocolError("NaN/infinity are forbidden")
        return
    if isinstance(value, list):
        for item in value:
            _check(item, depth + 1)
        return
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise ProtocolError("JSON object keys must be strings")
        for v in value.values():
            _check(v, depth + 1)
        return
    raise ProtocolError(f"JSON type forbidden: {type(value).__name__}")


def canonical(value: Any) -> bytes:
    _check(value)
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (UnicodeEncodeError, ValueError, TypeError) as exc:
        raise ProtocolError("non-canonical JSON value") from exc


def digest(domain: str, *parts: bytes | str | int) -> str:
    h = hashlib.sha256()
    label = domain.encode("ascii")
    h.update(len(label).to_bytes(4, "big") + label)
    for p in parts:
        if isinstance(p, str):
            p = p.encode("utf-8")
        elif isinstance(p, int):
            if p < 0 or p > 2**63 - 1:
                raise ProtocolError("out-of-range digest integer")
            p = p.to_bytes(8, "big")
        if not isinstance(p, bytes):
            raise ProtocolError("invalid digest part")
        h.update(len(p).to_bytes(8, "big") + p)
    return h.hexdigest()


def is_hex32(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def require_hex32(value: Any, name: str) -> None:
    if not is_hex32(value):
        raise ProtocolError(f"{name} must be lowercase 32-byte hex")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def unix_seconds(value: str) -> float:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ProtocolError("timestamp must use UTC Z suffix")
    try:
        d = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return d.timestamp()
    except (ValueError, OverflowError) as exc:
        raise ProtocolError("invalid timestamp") from exc


def validate_event(event: dict[str, Any], collector: str, epoch: int) -> None:
    required = {"event_id", "collector_id", "collector_epoch", "source_host", "event_type", "severity", "event_time_utc", "collector_monotonic_ns", "payload"}
    if not isinstance(event, dict) or set(event) != required:
        raise ProtocolError("invalid event schema")
    if event["collector_id"] != collector or event["collector_epoch"] != epoch:
        raise ProtocolError("collector/epoch mismatch")
    for key in ("event_id", "source_host", "event_type"):
        if not isinstance(event[key], str) or not event[key] or len(event[key]) > 256:
            raise ProtocolError(f"invalid {key}")
    if event["severity"] not in ("low", "medium", "high", "critical"):
        raise ProtocolError("invalid severity")
    if type(event["collector_monotonic_ns"]) is not int or event["collector_monotonic_ns"] < 0:
        raise ProtocolError("invalid monotonic timestamp")
    if not isinstance(event["payload"], dict):
        raise ProtocolError("payload must be an object")
    unix_seconds(event["event_time_utc"])
    if len(canonical(event)) > MAX_EVENT_BYTES:
        raise ProtocolError("event exceeds limit")


def genesis(collector: str, epoch: int) -> str:
    return digest("PABLA-GENESIS-v1", collector, epoch)


def event_hash(collector: str, epoch: int, sequence: int, event: dict[str, Any]) -> str:
    validate_event(event, collector, epoch)
    return digest("PABLA-EVENT-v1", collector, epoch, sequence, canonical(event))


def chain_hash(collector: str, epoch: int, sequence: int, previous: str, event_digest: str) -> str:
    require_hex32(previous, "previous chain")
    require_hex32(event_digest, "event digest")
    return digest("PABLA-CHAIN-v1", collector, epoch, sequence, bytes.fromhex(previous), bytes.fromhex(event_digest))


def leaf_hash(sequence: int, event_digest: str, chain_digest: str) -> str:
    return digest("PABLA-LEAF-v1", sequence, bytes.fromhex(event_digest), bytes.fromhex(chain_digest))


def merkle_root(leaves: list[str]) -> str:
    if not leaves or len(leaves) > MAX_BATCH:
        raise ProtocolError("invalid Merkle leaf count")
    for x in leaves:
        require_hex32(x, "leaf")
    level = leaves[:]
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])
        level = [digest("PABLA-NODE-v1", bytes.fromhex(level[i]), bytes.fromhex(level[i + 1])) for i in range(0, len(level), 2)]
    return level[0]


def merkle_proof(leaves: list[str], index: int) -> list[str]:
    if not (0 <= index < len(leaves)):
        raise ProtocolError("leaf index out of range")
    level = leaves[:]
    proof = []
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])
        proof.append(level[index ^ 1])
        index //= 2
        level = [digest("PABLA-NODE-v1", bytes.fromhex(level[i]), bytes.fromhex(level[i + 1])) for i in range(0, len(level), 2)]
    return proof


def verify_proof(leaf: str, proof: list[str], index: int, size: int, root: str) -> bool:
    if not 0 <= index < size or not 1 <= size <= MAX_BATCH:
        return False
    try:
        require_hex32(leaf, "leaf")
        require_hex32(root, "root")
        if len(proof) != (size - 1).bit_length():
            return False
        current = leaf
        level_size = size
        for sibling in proof:
            require_hex32(sibling, "sibling")
            if index == level_size - 1 and level_size % 2 and sibling != current:
                return False
            pair = (current, sibling) if not index % 2 else (sibling, current)
            current = digest("PABLA-NODE-v1", bytes.fromhex(pair[0]), bytes.fromhex(pair[1]))
            index //= 2
            level_size = (level_size + 1) // 2
        return current == root
    except ProtocolError:
        return False


def keypair() -> tuple[Ed25519PrivateKey, str]:
    sk = Ed25519PrivateKey.generate()
    return sk, public_hex(sk)


def public_hex(sk: Ed25519PrivateKey) -> str:
    return sk.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()


def sign(sk: Ed25519PrivateKey, message_hash: str) -> str:
    require_hex32(message_hash, "message hash")
    return sk.sign(bytes.fromhex(message_hash)).hex()


def valid_signature(public_key: str, message_hash: str, signature: str) -> bool:
    try:
        if not isinstance(public_key, str) or len(public_key) != 64 or not isinstance(signature, str) or len(signature) != 128:
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(bytes.fromhex(signature), bytes.fromhex(message_hash))
        return True
    except (ValueError, InvalidSignature):
        return False


@dataclass(frozen=True)
class Policy:
    name: str
    sign_batches: bool = True
    chain: bool = True
    link_manifests: bool = True
    anchor: bool = True
    revoke_check: bool = True
    timestamps: bool = True
    @staticmethod
    def for_name(name: str) -> 'Policy':
        presets = {
            "P1": {},
            "B1": {"sign_batches": False, "chain": False, "link_manifests": False},
            "B2": {"chain": False, "link_manifests": False, "anchor": False},
            "B3": {"sign_batches": False, "anchor": False, "link_manifests": False, "timestamps": False},
            "B4": {"chain": False, "link_manifests": False},
            "A1": {"chain": False},
            "A2": {"link_manifests": False},
            "A3": {"anchor": False},
            "A4": {"revoke_check": False},
            "A5": {"timestamps": False},
        }
        if name not in presets:
            raise ProtocolError(f"unknown method {name}")
        return Policy(name=name, **presets[name])


def manifest_hash(manifest: dict[str, Any]) -> str:
    return digest("PABLA-MANIFEST-v1", canonical(manifest))


@dataclass
class Batch:
    manifest: dict[str, Any]
    signature: str
    events: list[dict[str, Any]]
    manifest_digest: str
    leaves: list[str]
    def export(self) -> dict[str, Any]:
        return {"manifest": self.manifest, "signature": self.signature, "events": self.events, "manifest_digest": self.manifest_digest}


@dataclass
class Collector:
    collector_id: str
    epoch: int
    private_key: Ed25519PrivateKey
    policy: Policy = field(default_factory=lambda: Policy.for_name("P1"))
    next_sequence: int = 1
    next_batch: int = 1
    last_chain: str = ""
    last_manifest: str = ZERO
    def __post_init__(self) -> None:
        if self.epoch < 1 or not self.collector_id:
            raise ProtocolError("invalid collector identity")
        if not self.last_chain:
            self.last_chain = genesis(self.collector_id, self.epoch)
    def collect(self, events: list[dict[str, Any]], *, wall_time: str | None = None, monotonic_ns: int | None = None) -> Batch:
        if not 1 <= len(events) <= MAX_BATCH:
            raise ProtocolError("batch count out of range")
        start = self.next_sequence
        prev = self.last_chain
        leaves = []
        for ev in events:
            seq = self.next_sequence
            h = event_hash(self.collector_id, self.epoch, seq, ev)
            self.last_chain = chain_hash(self.collector_id, self.epoch, seq, self.last_chain, h) if self.policy.chain else ZERO
            leaves.append(leaf_hash(seq, h, self.last_chain))
            self.next_sequence += 1
        wall = wall_time or utc_now()
        unix_seconds(wall)
        m = {
            "protocol_version": PROTOCOL,
            "collector_id": self.collector_id,
            "epoch": self.epoch,
            "batch_number": self.next_batch,
            "first_sequence": start,
            "last_sequence": self.next_sequence - 1,
            "event_count": len(events),
            "first_previous_chain": prev if self.policy.chain else ZERO,
            "last_chain": self.last_chain if self.policy.chain else ZERO,
            "merkle_root": merkle_root(leaves),
            "previous_manifest_hash": self.last_manifest if self.policy.link_manifests else ZERO,
            "wall_time": wall,
            "monotonic_ns": monotonic_ns if monotonic_ns is not None else time.monotonic_ns(),
            "method": self.policy.name,
        }
        mh = manifest_hash(m)
        sig = sign(self.private_key, mh) if self.policy.sign_batches else ""
        batch = Batch(m, sig, list(events), mh, leaves)
        self.last_manifest = mh
        self.next_batch += 1
        return batch


@dataclass
class Verdict:
    status: str
    anomalies: list[str]
    manifest_digest: str | None = None
    def as_dict(self) -> dict[str, Any]:
        return {"status": self.status, "anomalies": self.anomalies, "manifest_digest": self.manifest_digest}


def verify_batch(batch: Batch | dict[str, Any] | None, ledger: Any, *, policy: Policy,
                 previous: dict[str, Any] | None = None, max_skew_seconds: float = 300.0) -> Verdict:
    if not isinstance(policy, Policy):
        raise ProtocolError("trusted verification policy is required")
    if batch is None:
        return Verdict("UNDETERMINED_ARCHIVE_MISSING", ["ARCHIVE_MISSING"])
    try:
        if isinstance(batch, dict):
            batch = Batch(batch["manifest"], batch["signature"], batch["events"], batch["manifest_digest"], [])
        m = batch.manifest
        if not isinstance(m, dict) or m.get("protocol_version") != PROTOCOL:
            raise ProtocolError("wrong manifest version")
        method = policy
        if m.get("method") != method.name:
            return Verdict("REJECT_AUTHORIZATION", ["POLICY_DOWNGRADE"])
        collector, epoch = m["collector_id"], m["epoch"]
        bn, first, last, count = (m[k] for k in ("batch_number", "first_sequence", "last_sequence", "event_count"))
        if any(type(x) is not int or x < 1 for x in (epoch, bn, first, last, count)) or count != last - first + 1 or count > MAX_BATCH:
            return Verdict("REJECT_CONTINUITY", ["RANGE_INVALID"])
        if len(batch.events) != count:
            return Verdict("REJECT_CONTINUITY", ["SEQUENCE_GAP"])
        if m["monotonic_ns"] < 0 or type(m["monotonic_ns"]) is not int:
            raise ProtocolError("invalid monotonic value")
        recorded_digest = manifest_hash(m)
        if recorded_digest != batch.manifest_digest:
            return Verdict("REJECT_CONTENT_INTEGRITY", ["MANIFEST_DIGEST_MISMATCH"])
        identity = ledger.identity(collector, epoch)
        if identity and identity.get("policy") != method.name:
            return Verdict("REJECT_AUTHORIZATION", ["REGISTRY_POLICY_MISMATCH"])
        if method.sign_batches:
            if not identity:
                return Verdict("REJECT_AUTHORIZATION", ["UNREGISTERED_COLLECTOR"])
            if not valid_signature(identity["public_key"], recorded_digest, batch.signature):
                return Verdict("REJECT_AUTHORIZATION", ["INVALID_SIGNATURE"])
        warnings: list[str] = []
        if previous is None:
            if bn != 1 or first != 1:
                return Verdict("REJECT_CONTINUITY", ["MISSING_PREDECESSOR"])
            chain_prev = genesis(collector, epoch)
            if method.link_manifests and m["previous_manifest_hash"] != ZERO:
                return Verdict("REJECT_CONTINUITY", ["PREVIOUS_MANIFEST_MISMATCH"])
        else:
            if bn != previous["batch_number"] + 1 or first != previous["last_sequence"] + 1:
                return Verdict("REJECT_CONTINUITY", ["BATCH_OR_SEQUENCE_GAP"])
            chain_prev = previous["last_chain"]
            if method.link_manifests and m["previous_manifest_hash"] != manifest_hash(previous):
                return Verdict("REJECT_CONTINUITY", ["PREVIOUS_MANIFEST_MISMATCH"])
            if method.timestamps and m["monotonic_ns"] < previous["monotonic_ns"]:
                warnings.append("MONOTONIC_REGRESSION")
        if method.chain and m["first_previous_chain"] != chain_prev:
            return Verdict("REJECT_CONTINUITY", ["CHAIN_LINK_MISMATCH"])
        curr_chain = chain_prev
        leaves = []
        observed_ids = set()
        last_mono = -1
        for idx, ev in enumerate(batch.events):
            if ev["event_id"] in observed_ids:
                return Verdict("REJECT_CONTINUITY", ["DUPLICATE_EVENT_ID"])
            observed_ids.add(ev["event_id"])
            if ev["collector_monotonic_ns"] < last_mono:
                return Verdict("REJECT_CONTINUITY", ["EVENT_MONOTONIC_REGRESSION"])
            last_mono = ev["collector_monotonic_ns"]
            seq = first + idx
            h = event_hash(collector, epoch, seq, ev)
            curr_chain = chain_hash(collector, epoch, seq, curr_chain, h) if method.chain else ZERO
            leaves.append(leaf_hash(seq, h, curr_chain))
        if method.chain and curr_chain != m["last_chain"]:
            return Verdict("REJECT_CONTENT_INTEGRITY", ["CHAIN_DIGEST_MISMATCH"])
        if merkle_root(leaves) != m["merkle_root"]:
            return Verdict("REJECT_CONTENT_INTEGRITY", ["MERKLE_ROOT_MISMATCH"])
        anchor = None
        if method.anchor:
            anchor = ledger.anchor_record(collector, epoch, bn)
            if not anchor:
                return Verdict("REJECT_ANCHOR", ["ANCHOR_MISSING"])
            if anchor["manifest_hash"] != recorded_digest or anchor["merkle_root"] != m["merkle_root"] or anchor["last_chain"] != m["last_chain"] or anchor["first_sequence"] != first or anchor["last_sequence"] != last:
                return Verdict("REJECT_ANCHOR", ["ANCHOR_MISMATCH"])
            if method.revoke_check and identity and identity.get("revoked_block") and anchor["block_number"] >= identity["revoked_block"]:
                return Verdict("REJECT_AUTHORIZATION", ["REVOKED_EPOCH"])
        if method.timestamps:
            timestamp = unix_seconds(m["wall_time"])
            if anchor and abs(timestamp - anchor["block_timestamp"]) > max_skew_seconds:
                warnings.append("CLOCK_SKEW")
            if any(abs(unix_seconds(ev["event_time_utc"]) - timestamp) > max_skew_seconds for ev in batch.events):
                warnings.append("EVENT_CLOCK_SKEW")
        return Verdict("ACCEPT_WITH_WARNING" if warnings else "ACCEPT", warnings, recorded_digest)
    except (ProtocolError, ValueError, KeyError, TypeError, IndexError, AttributeError) as exc:
        return Verdict("REJECT_CONTENT_INTEGRITY", ["MALFORMED_ARTIFACT", type(exc).__name__])


def verify_history(batches: list[Batch | dict[str, Any] | None], ledger: Any, policy: Policy) -> list[Verdict]:
    previous = None
    out = []
    for batch in batches:
        result = verify_batch(batch, ledger, policy=policy, previous=previous)
        out.append(result)
        if result.status in ("ACCEPT", "ACCEPT_WITH_WARNING") and batch is not None:
            previous = batch.manifest if isinstance(batch, Batch) else batch["manifest"]
    return out


def verify_complete_history(batches: list[Batch | dict[str, Any] | None], ledger: Any, *,
                            policy: Policy, collector_id: str, epoch: int) -> list[Verdict]:
    """Validate a complete archive against an independently queried on-chain tip.

    A missing archive cannot pass as complete merely because its prefix is valid.
    The trusted collector/epoch selector must not be sourced from the archive.
    """
    tip_batch, tip_sequence = ledger.latest(collector_id, epoch)
    verdicts = verify_history(batches, ledger, policy)
    if not batches:
        return [Verdict("REJECT_CONTINUITY", ["TRUNCATION"]) ] if tip_batch else []
    last = batches[-1]
    if last is None:
        return verdicts + [Verdict("UNDETERMINED_ARCHIVE_MISSING", ["ARCHIVE_MISSING"])]
    m = last.manifest if isinstance(last, Batch) else last.get("manifest", {})
    if not isinstance(m, dict) or m.get("collector_id") != collector_id or m.get("epoch") != epoch:
        return verdicts + [Verdict("REJECT_CONTINUITY", ["HISTORY_SCOPE_MISMATCH"])]
    if policy.anchor and (m.get("batch_number") != tip_batch or m.get("last_sequence") != tip_sequence):
        verdicts.append(Verdict("REJECT_CONTINUITY", ["TRUNCATION"]))
    return verdicts
