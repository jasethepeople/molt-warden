"""Minimal MOLT-CORE Camp 1 package verifier for signed trial evidence."""
from __future__ import annotations

import hashlib
import json
import math
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .bundle import Bundle, BundleError

ZERO_HASH = "0" * 64
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX128 = re.compile(r"[0-9a-f]{128}\Z")
EVENT_FIELDS = {"seq", "ts", "type", "actor", "payload", "prev_hash", "pub", "sig", "hash"}
BODY_FIELDS = ("seq", "ts", "type", "payload", "actor")
ED25519_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
MAX_MANIFEST = 1_000_000
MAX_LEDGER = 32 * 1024 * 1024
MAX_EVENTS = 10_000
SAFE_INTEGER = 9_007_199_254_740_991
MAX_LINE = 256 * 1024


class MoltError(Exception):
    """A MOLT-CORE evidence package is invalid or cannot be verified."""


@dataclass(frozen=True)
class MoltEvent:
    seq: int
    ts: int
    type: str
    actor: str
    payload: object
    prev_hash: str
    pub: str
    sig: str
    hash: str


def _json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(raw: bytes, label: str):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_json_pairs,
                          parse_constant=lambda v: (_ for _ in ()).throw(ValueError(f"invalid JSON constant {v}")))
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise MoltError(f"{label}: invalid JSON ({exc})") from exc


def _number(value: float) -> str:
    if not math.isfinite(value):
        raise MoltError("non-finite JSON number is not canonicalizable")
    if value == 0:
        return "0"
    raw = repr(value).lower()
    if "e" not in raw:
        if raw.endswith(".0"):
            return raw[:-2]
        return raw
    mantissa, exp_text = raw.split("e", 1)
    exp = int(exp_text)
    sign = ""
    if mantissa.startswith("-"):
        sign, mantissa = "-", mantissa[1:]
    whole, dot, fraction = mantissa.partition(".")
    digits = whole + fraction
    decimal_at = len(whole) + exp
    if -6 < decimal_at <= 21:
        if decimal_at <= 0:
            return sign + "0." + "0" * (-decimal_at) + digits
        if decimal_at >= len(digits):
            return sign + digits + "0" * (decimal_at - len(digits))
        return sign + digits[:decimal_at] + "." + digits[decimal_at:]
    coefficient = digits[0] + (("." + digits[1:]) if len(digits) > 1 else "")
    exponent = decimal_at - 1
    return sign + coefficient + "e" + ("+" if exponent >= 0 else "") + str(exponent)


def canonical_json(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > SAFE_INTEGER:
            raise MoltError("JSON integer exceeds the interoperable safe-integer range")
        return str(value)
    if isinstance(value, float):
        return _number(value)
    if isinstance(value, str):
        if not value.isascii():
            raise MoltError("non-ASCII strings remain an open MOLT-CORE canonicalization decision")
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        if any(not isinstance(key, str) or not key.isascii() for key in value):
            raise MoltError("non-ASCII object keys remain an open MOLT-CORE canonicalization decision")
        return "{" + ",".join(canonical_json(key) + ":" + canonical_json(value[key]) for key in sorted(value)) + "}"
    raise MoltError(f"unsupported JSON value type: {type(value).__name__}")


def _safe_file(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise MoltError(f"unsafe artifact path: {relative!r}")
    parts = relative.split("/")
    if "transcript.md" in parts:
        raise MoltError("transcript.md is excluded from all bundle reads")
    if relative.startswith("/") or any(p in ("", ".", "..") for p in parts):
        raise MoltError(f"unsafe artifact path: {relative!r}")
    path = root
    for part in parts:
        path = path / part
        if path.is_symlink():
            raise MoltError(f"symlink in MOLT package path: {relative}")
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise MoltError(f"missing or escaping MOLT package path: {relative}") from exc
    if not path.is_file():
        raise MoltError(f"MOLT artifact is not a regular file: {relative}")
    return path


def _verify_signature(public_pem: Path, signature: bytes, message: bytes) -> None:
    executable = shutil.which("openssl")
    if not executable:
        raise MoltError("OpenSSL is required to verify Ed25519 signatures")
    with tempfile.TemporaryDirectory(prefix="warden-sig-") as td:
        sig_path = Path(td) / "signature.bin"
        msg_path = Path(td) / "message.bin"
        sig_path.write_bytes(signature)
        msg_path.write_bytes(message)
        try:
            result = subprocess.run(
                [executable, "pkeyutl", "-verify", "-pubin", "-inkey", str(public_pem),
                 "-sigfile", str(sig_path), "-in", str(msg_path), "-rawin"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise MoltError(f"Ed25519 verification could not run: {exc}") from exc
    if result.returncode != 0:
        raise MoltError("MOLT event Ed25519 signature is invalid")


def _public_key_bytes(public_pem: Path) -> bytes:
    executable = shutil.which("openssl")
    if not executable:
        raise MoltError("OpenSSL is required to verify Ed25519 signatures")
    try:
        result = subprocess.run([executable, "pkey", "-pubin", "-in", str(public_pem), "-outform", "DER"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MoltError(f"cannot parse MOLT public key: {exc}") from exc
    der = result.stdout
    if result.returncode != 0 or len(der) != 44 or not der.startswith(ED25519_DER_PREFIX):
        raise MoltError("ed25519-public.pem is not a valid Ed25519 public key")
    return der[-32:]


def load_ledger(bundle: Bundle) -> list[MoltEvent]:
    root = bundle.path("stores/ledger")
    if root.is_symlink() or not root.is_dir():
        raise MoltError("stores/ledger: expected a MOLT-CORE package directory")
    manifest_path = _safe_file(root, "manifest.json")
    ledger_path = _safe_file(root, "events.jsonl")
    public_path = _safe_file(root, "ed25519-public.pem")
    if manifest_path.stat().st_size > MAX_MANIFEST:
        raise MoltError("stores/ledger/manifest.json exceeds 1 MB")
    if ledger_path.stat().st_size > MAX_LEDGER:
        raise MoltError("stores/ledger/events.jsonl exceeds 32 MiB")
    manifest = _load_json(manifest_path.read_bytes(), "stores/ledger/manifest.json")
    if not isinstance(manifest, dict):
        raise MoltError("MOLT manifest root must be an object")
    for key in ("ledger_bytes", "agent_pubkeys", "artifacts", "artifact_bytes"):
        if key not in manifest:
            raise MoltError(f"MOLT manifest missing {key}")
    raw = ledger_path.read_bytes()
    if type(manifest["ledger_bytes"]) is not int or manifest["ledger_bytes"] < 0 or manifest["ledger_bytes"] != len(raw):
        raise MoltError("MOLT ledger byte count does not match manifest")
    if raw and not raw.endswith(b"\n"):
        raise MoltError("MOLT ledger is missing its final newline")
    if not isinstance(manifest["agent_pubkeys"], dict) or not isinstance(manifest["artifacts"], dict) or not isinstance(manifest["artifact_bytes"], dict):
        raise MoltError("MOLT manifest maps must be JSON objects")
    artifacts = {rel: digest for rel, digest in manifest["artifacts"].items() if not (isinstance(rel, str) and "transcript.md" in rel.split("/"))}
    artifact_bytes = {rel: size for rel, size in manifest["artifact_bytes"].items() if not (isinstance(rel, str) and "transcript.md" in rel.split("/"))}
    if set(artifacts) != set(artifact_bytes):
        raise MoltError("MOLT artifact digest and byte-count maps differ")
    for rel, digest in artifacts.items():
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise MoltError(f"invalid MOLT artifact digest: {rel}")
        size = artifact_bytes.get(rel)
        if type(size) is not int or size < 0:
            raise MoltError(f"invalid MOLT artifact byte count: {rel}")
        path = _safe_file(root, rel)
        if path.stat().st_size != size or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise MoltError(f"MOLT artifact digest/size mismatch: {rel}")
    public_bytes = _public_key_bytes(public_path)
    public_hex = public_bytes.hex()
    event_lines = raw.splitlines(keepends=True)
    if len(event_lines) > MAX_EVENTS:
        raise MoltError(f"MOLT ledger exceeds {MAX_EVENTS} signed events")
    previous = ZERO_HASH
    events: list[MoltEvent] = []
    for position, line in enumerate(event_lines):
        if len(line) > MAX_LINE:
            raise MoltError(f"MOLT event line {position} exceeds 256 KiB")
        try:
            text = line[:-1].decode("utf-8")
        except UnicodeError as exc:
            raise MoltError(f"MOLT event line {position} is not UTF-8") from exc
        obj = _load_json(text.encode("utf-8"), f"MOLT event line {position}")
        if not isinstance(obj, dict) or set(obj) != EVENT_FIELDS:
            raise MoltError(f"MOLT event line {position} must contain exactly nine Camp 1 fields")
        if text != canonical_json(obj):
            raise MoltError(f"MOLT event line {position} is not canonical JSON")
        if type(obj["seq"]) is not int or obj["seq"] != position or obj["seq"] < 0:
            raise MoltError(f"MOLT event line {position} has an invalid sequence")
        if type(obj["ts"]) is not int or obj["ts"] < 0:
            raise MoltError(f"MOLT event line {position} has an invalid timestamp")
        if not isinstance(obj["type"], str) or not isinstance(obj["actor"], str):
            raise MoltError(f"MOLT event line {position} type/actor must be strings")
        for field, pattern in (("prev_hash", HEX64), ("hash", HEX64), ("pub", HEX64), ("sig", HEX128)):
            if not isinstance(obj[field], str) or not pattern.fullmatch(obj[field]):
                raise MoltError(f"MOLT event line {position} has malformed {field}")
        if obj["prev_hash"] != previous:
            raise MoltError(f"MOLT event line {position} does not extend the recomputed hash chain")
        if obj["pub"] != public_hex or manifest["agent_pubkeys"].get(obj["actor"]) != public_hex:
            raise MoltError(f"MOLT event line {position} actor/public-key binding failed")
        body = {key: obj[key] for key in BODY_FIELDS}
        body_bytes = canonical_json(body).encode("utf-8")
        recomputed = hashlib.sha256(obj["prev_hash"].encode("ascii") + body_bytes).hexdigest()
        if recomputed != obj["hash"]:
            raise MoltError(f"MOLT event line {position} hash mismatch")
        _verify_signature(public_path, bytes.fromhex(obj["sig"]), bytes.fromhex(recomputed))
        event = MoltEvent(seq=obj["seq"], ts=obj["ts"], type=obj["type"], actor=obj["actor"],
                          payload=obj["payload"], prev_hash=obj["prev_hash"], pub=obj["pub"],
                          sig=obj["sig"], hash=recomputed)
        events.append(event)
        previous = recomputed
    anchor = manifest.get("anchor")
    if anchor is not None:
        if not isinstance(anchor, dict) or type(anchor.get("seq")) is not int or not HEX64.fullmatch(str(anchor.get("hash", ""))):
            raise MoltError("MOLT manifest anchor is malformed")
        if anchor["seq"] < 0 or anchor["seq"] >= len(events) or events[anchor["seq"]].hash != anchor["hash"]:
            raise MoltError("MOLT manifest anchor does not match recomputed ledger")
    return events
