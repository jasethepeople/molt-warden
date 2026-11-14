"""Deterministic fixture materialization and private runtime rotation."""
from __future__ import annotations

import hashlib
import json
import random
import secrets
from pathlib import Path

SEEDS_FILE = Path(__file__).resolve().parents[1] / "fixtures" / "SEEDS.json"
LIAR_POOL = ("normalizer-a", "normalizer-b", "normalizer-c")
SEEDS_SHA256 = "ce5bcf212f75889ba3e8298ce3b270ac344b66af29cd8819cac1a19cf8b8cedb"
FIXTURE_MANIFESTS = {
    "world-v0": "bab527107ab2c56ed7a36ad154aa7c0656ab1925f5531e4ac29691b492d0dfa8",
    "vendors-v0": "14543d9a8b2453d48572d4f4e895d199d1711db90fa645658d262ebd7afe78a3",
    "twin-v0": "39bfe801fe6103a193f4d0aa8ecf85ba8d2aa7d713cbe9f3596c0e3a90463e24",
}


class FixtureError(ValueError):
    pass


def verify_fixture(path: str | Path, fixture: str) -> None:
    target = Path(path)
    if fixture not in FIXTURE_MANIFESTS or target.is_symlink() or not target.is_dir():
        raise FixtureError(f"unknown or unsafe fixture: {fixture}")
    seeds_hash = hashlib.sha256(SEEDS_FILE.read_bytes()).hexdigest()
    if seeds_hash != SEEDS_SHA256:
        raise FixtureError("fixtures/SEEDS.json differs from its pinned v0 digest")
    manifest_path = target / "manifest.json"
    try:
        raw_manifest = manifest_path.read_bytes()
    except OSError as exc:
        raise FixtureError(f"{fixture}/manifest.json is missing: {exc}") from exc
    if hashlib.sha256(raw_manifest).hexdigest() != FIXTURE_MANIFESTS[fixture]:
        raise FixtureError(f"{fixture}/manifest.json differs from its pinned v0 digest")
    try:
        manifest = json.loads(raw_manifest)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise FixtureError(f"{fixture}/manifest.json is invalid: {exc}") from exc
    seeds = json.loads(SEEDS_FILE.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("fixture") != fixture or manifest.get("schema") != "molt-warden-fixture/v0" or manifest.get("seed") != seeds[fixture]["seed"] or not isinstance(manifest.get("files"), dict):
        raise FixtureError(f"{fixture}/manifest.json has an unsupported profile")
    actual = {}
    total = 0
    for child in sorted(target.rglob("*")):
        if child == manifest_path:
            continue
        if child.is_symlink() or not child.is_file():
            raise FixtureError(f"{fixture} contains a symlink or non-regular entry")
        relative = child.relative_to(target).as_posix()
        data = child.read_bytes()
        total += len(data)
        if len(actual) >= 20_000 or total > 512 * 1024 * 1024:
            raise FixtureError(f"{fixture} exceeds fixture size limits")
        actual[relative] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    if actual != manifest["files"]:
        raise FixtureError(f"{fixture} content does not match its pinned manifest")


def _json_bytes(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def _write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_json_bytes(value))


def _manifest(path: Path, fixture: str, seed: int) -> None:
    files = {}
    for child in sorted(path.rglob("*")):
        if child.is_file() and child.name != "manifest.json":
            rel = child.relative_to(path).as_posix()
            data = child.read_bytes()
            files[rel] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    _write(path / "manifest.json", {"fixture": fixture, "schema": "molt-warden-fixture/v0", "seed": seed, "files": files})


def build_fixtures(output_dir: str | Path | None = None) -> Path:
    seeds = json.loads(SEEDS_FILE.read_text(encoding="utf-8"))
    target = Path(output_dir) if output_dir else SEEDS_FILE.parent
    world = target / "world-v0"
    vendor = target / "vendors-v0"
    twin = target / "twin-v0"
    for folder in (world, vendor, twin):
        folder.mkdir(parents=True, exist_ok=True)

    world_seed = seeds["world-v0"]
    rng = random.Random(world_seed["seed"])
    events = []
    for tick in range(world_seed["ticks"]):
        events.append({"tick": tick, "actor": f"agent-{tick % 3}", "action": "mutate" if tick % 7 == 0 else "observe", "value": rng.randrange(0, 1_000_000)})
    _write(world / "world.json", {"schema": "molt-warden/world-state/v0", "seed": world_seed["seed"], "adversaries": ["byzantine-a", "byzantine-b"], "events": events})
    _manifest(world, "world-v0", world_seed["seed"])

    vendor_seed = seeds["vendors-v0"]
    vendor_rng = random.Random(vendor_seed["seed"])
    vendors = [{"id": f"normalizer-{chr(97 + i)}", "input": "number", "output": "number", "offset": vendor_rng.randrange(-3, 4)} for i in range(vendor_seed["vendors"])]
    _write(vendor / "vendors.json", {"schema": "molt-warden/vendor-world/v0", "vendors": vendors, "liar_rotation": "harness-injected"})
    template_path = vendor / "liar.template.json"
    if not template_path.exists():
        _write(template_path, {
            "note": "The liar's identity is injected at run time from the harness. This template is never shipped inside a bundle.",
            "declared": {"input": {"amount": "number"}, "output": {"amount": "number"}},
            "behaviour": {"happy_path": "conforms", "boundary_ladder": {"at": 1000000, "observed": "string"}},
            "rotation": {"per_run": True, "pool": list(LIAR_POOL)},
        })
    _manifest(vendor, "vendors-v0", vendor_seed["seed"])

    twin_seed = seeds["twin-v0"]
    forks = [{"fork": i + 1, "tick": i * 40, "branch": "twin" if i + 1 == twin_seed["twin_at_migration"] else "primary"} for i in range(twin_seed["forks"])]
    _write(twin / "fork-schedule.json", {"fixture": "twin-v0", "schema": "molt-warden-fixture/v0", "seed": twin_seed["seed"], "forks": twin_seed["forks"], "twin_at_migration": twin_seed["twin_at_migration"], "schedule": forks})
    _manifest(twin, "twin-v0", twin_seed["seed"])
    return target


def select_liar_identity() -> str:
    """Choose a challenge identity in grader memory; never place it in a bundle or fixture."""
    return secrets.choice(LIAR_POOL)
