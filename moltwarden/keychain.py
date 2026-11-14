"""Verify an explicitly encoded Ed25519 delegation chain from its root."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from .bundle import Bundle, BundleError, read_json
from .molt import MoltError, _public_key_bytes, _verify_signature, canonical_json

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX128 = re.compile(r"[0-9a-f]{128}\Z")


class KeychainError(Exception):
    """Public-key chain is absent, malformed, or cryptographically invalid."""


@dataclass(frozen=True)
class VerifiedKeychain:
    current_id: str
    current_pem: Path
    current_sha256: str
    ids: tuple[str, ...]
    public_keys: tuple[tuple[str, str], ...]


def verify_keychain(bundle: Bundle) -> VerifiedKeychain:
    try:
        path = bundle.path("keys/delegation.json")
        manifest = read_json(path)
        if not isinstance(manifest, dict) or manifest.get("format") != "molt-warden-keychain/v1":
            raise KeychainError("keys/delegation.json: unsupported keychain format")
        root = manifest.get("root")
        links = manifest.get("delegations")
        current = manifest.get("current")
        if not isinstance(root, dict) or not isinstance(root.get("id"), str) or not isinstance(root.get("public_key"), str) or not isinstance(root.get("sha256"), str) or not HEX64.fullmatch(root["sha256"]):
            raise KeychainError("keys/delegation.json: malformed genesis key")
        if not isinstance(links, list) or not isinstance(current, str):
            raise KeychainError("keys/delegation.json: delegations must be an array and current must be a key ID")
        root_pem = bundle.path("keys/" + root["public_key"])
        root_bytes = _public_key_bytes(root_pem)
        root_hash = hashlib.sha256(root_bytes).hexdigest()
        if root_hash != root["sha256"]:
            raise KeychainError("keys/delegation.json: genesis public-key digest mismatch")
        keys = {root["id"]: (root_pem, root_hash)}
        public_keys = {root["id"]: root_bytes.hex()}
        chain_ids = [root["id"]]
        for index, link in enumerate(links):
            if not isinstance(link, dict):
                raise KeychainError(f"keys/delegation.json: malformed delegation link {index}")
            issuer, subject = link.get("issuer"), link.get("subject")
            public_name = link.get("public_key")
            issuer_hash, subject_hash, signature = link.get("issuer_key_sha256"), link.get("subject_key_sha256"), link.get("signature")
            if not all(isinstance(value, str) and value for value in (issuer, subject, public_name)):
                raise KeychainError(f"keys/delegation.json: incomplete delegation link {index}")
            if issuer not in keys or subject in keys or keys[issuer][1] != issuer_hash:
                raise KeychainError(f"keys/delegation.json: link {index} does not extend the verified chain")
            if not isinstance(subject_hash, str) or not HEX64.fullmatch(subject_hash) or not isinstance(signature, str) or not HEX128.fullmatch(signature):
                raise KeychainError(f"keys/delegation.json: malformed key digest/signature in link {index}")
            subject_pem = bundle.path("keys/" + public_name)
            subject_raw = _public_key_bytes(subject_pem)
            actual_subject_hash = hashlib.sha256(subject_raw).hexdigest()
            if actual_subject_hash != subject_hash:
                raise KeychainError(f"keys/delegation.json: subject public-key digest mismatch in link {index}")
            signed = {key: value for key, value in link.items() if key != "signature"}
            _verify_signature(keys[issuer][0], bytes.fromhex(signature), canonical_json(signed).encode("ascii"))
            keys[subject] = (subject_pem, subject_hash)
            public_keys[subject] = subject_raw.hex()
            chain_ids.append(subject)
        if current not in keys:
            raise KeychainError("keys/delegation.json: current key is not descended from genesis")
        if current != chain_ids[-1]:
            raise KeychainError("keys/delegation.json: current key is not the tip of the declared chain")
        return VerifiedKeychain(current, *keys[current], tuple(chain_ids), tuple((key_id, public_keys[key_id]) for key_id in chain_ids))
    except (BundleError, MoltError, OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        if isinstance(exc, KeychainError):
            raise
        raise KeychainError(str(exc)) from exc
