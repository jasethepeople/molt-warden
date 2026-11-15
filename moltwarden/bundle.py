"""Safe bundle discovery, manifest validation, and path confinement."""
from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

REQUIRED = ("manifest.json", "anchors", "stores", "keys", "artifacts", "replay.sh")
TRIAL_FIXTURE = {"I": "world-v0", "II": "world-v0", "III": "vendors-v0", "IV": "twin-v0"}
MAX_FILES = 20_000
MAX_BUNDLE_BYTES = 512 * 1024 * 1024
FORBIDDEN_IN_KEYS = (
    b"-----begin private key-----", b"-----begin rsa private key-----",
    b"-----begin ec private key-----", b"-----begin openssh private key-----",
    b"-----begin encrypted private key-----", b"ed25519_priv", b"private_key",
    b"privatekey", b"privatekeyhex", b"privatekeybase64", b"secretkey", b"signingkey",
    b"seedhex", b"seedbase64",
)
SOURCE_SUFFIXES = {".py", ".pyc", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".rs", ".go", ".java", ".rb", ".php", ".sh", ".bash", ".zsh", ".c", ".h", ".cc", ".cpp", ".so", ".dll", ".class", ".wasm", ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".jar"}
ROOT_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")


class BundleError(Exception):
    """Bundle invalid ⇒ VOID, not FAIL."""


def _pairs_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs_no_duplicates,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"invalid JSON constant: {value}")))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise BundleError(f"{path.name}: invalid JSON ({exc})") from exc


@dataclass
class Bundle:
    root: Path
    manifest: dict
    cache: dict = field(default_factory=dict)

    @property
    def id(self) -> str:
        return self.manifest["bundle_id"]

    @property
    def trial(self) -> str:
        return self.manifest["trial"]

    def path(self, rel: str) -> Path:
        if not isinstance(rel, str) or not rel or "\\" in rel:
            raise BundleError(f"unsafe bundle path: {rel!r}")
        parts = rel.split("/")
        if "transcript.md" in parts:
            raise BundleError("transcript.md is excluded from all bundle reads")
        if rel.startswith("/") or any(part in ("", ".", "..") for part in parts):
            raise BundleError(f"unsafe bundle path: {rel!r}")
        candidate = self.root
        for part in parts:
            candidate = candidate / part
            try:
                if candidate.is_symlink():
                    raise BundleError(f"symlink is not allowed: {rel}")
            except OSError as exc:
                raise BundleError(f"cannot inspect bundle path {rel}: {exc}") from exc
        try:
            candidate.resolve(strict=True).relative_to(self.root.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise BundleError(f"path is missing or escapes bundle: {rel}") from exc
        return candidate

    def state_root(self) -> str:
        try:
            value = self.path("artifacts/state_root.txt").read_text(encoding="ascii").strip()
        except (OSError, UnicodeError, BundleError) as exc:
            raise BundleError(f"artifacts/state_root.txt: cannot read state root ({exc})") from exc
        if not ROOT_HASH.fullmatch(value):
            raise BundleError("artifacts/state_root.txt: malformed sha256 root")
        return value


def _inventory(root: Path) -> tuple[int, int]:
    count = total = 0
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        here = Path(current)
        for name in list(dirs):
            if name == "transcript.md":
                dirs.remove(name)
                continue
            path = here / name
            try:
                mode = path.lstat().st_mode
            except OSError as exc:
                raise BundleError(f"cannot inspect {path.relative_to(root)}: {exc}") from exc
            if stat.S_ISLNK(mode):
                raise BundleError(f"symlink is not allowed: {path.relative_to(root)}")
            if not stat.S_ISDIR(mode):
                raise BundleError(f"non-directory entry in bundle: {path.relative_to(root)}")
            count += 1
        for name in files:
            if name == "transcript.md":
                continue
            path = here / name
            try:
                mode = path.lstat().st_mode
                metadata = path.stat(follow_symlinks=False)
                size = metadata.st_size
            except OSError as exc:
                raise BundleError(f"cannot inspect {path.relative_to(root)}: {exc}") from exc
            if stat.S_ISLNK(mode) or not stat.S_ISREG(mode) or metadata.st_nlink > 1:
                raise BundleError(f"symlink, hardlink, or special file is not allowed: {path.relative_to(root)}")
            count += 1
            total += size
            if count > MAX_FILES:
                raise BundleError(f"bundle contains more than {MAX_FILES} entries")
            if total > MAX_BUNDLE_BYTES:
                raise BundleError(f"bundle exceeds {MAX_BUNDLE_BYTES} byte size limit")
    if count > MAX_FILES:
        raise BundleError(f"bundle contains more than {MAX_FILES} entries")
    return count, total


def _check_keys(root: Path) -> None:
    keys = root / "keys"
    allowed = {".pub", ".pem", ".json", ".jsonl", ".txt"}
    for current, dirs, files in os.walk(keys, topdown=True, followlinks=False):
        for name in list(dirs):
            if name == "transcript.md":
                dirs.remove(name)
                continue
            if (Path(current) / name).is_symlink():
                raise BundleError(f"symlink in keys/: {Path(current, name).relative_to(root)}")
        for name in files:
            if name == "transcript.md":
                continue
            path = Path(current) / name
            if path.suffix.lower() not in allowed:
                raise BundleError(f"non-public-key file type in keys/: {path.relative_to(root)}")
            try:
                data = path.read_bytes().lower()
            except OSError as exc:
                raise BundleError(f"cannot read keys file {path.relative_to(root)}: {exc}") from exc
            if any(marker in data for marker in FORBIDDEN_IN_KEYS):
                raise BundleError(f"private key material in keys/: {path.relative_to(root)}")
            if b"private key" in data or b"openssh private" in data or b'"privatekey"' in data:
                raise BundleError(f"private key material in keys/: {path.relative_to(root)}")
            if path.suffix.lower() == ".pem" and data.startswith(b"-----begin ") and b"public key-----" not in data and b"certificate-----" not in data:
                raise BundleError(f"non-public PEM material in keys/: {path.relative_to(root)}")


def _check_trial_specific(root: Path, trial: str) -> None:
    if trial in ("II", "IV"):
        attacks = root / "attacks"
        if not attacks.is_dir():
            raise BundleError(f"trial {trial} requires an attacks/ directory")
        scripts = [path for path in attacks.rglob("*") if "transcript.md" not in path.relative_to(root).parts and path.is_file() and path.suffix.lower() in {".sh", ".py"}]
        if len(scripts) != 1 or scripts[0].parent != attacks:
            raise BundleError(f"trial {trial} requires exactly one direct .sh or .py attack script in attacks/")
    if trial == "III":
        probes = root / "probes"
        if not probes.is_dir():
            raise BundleError("trial III requires probes/ I/O fixtures")
        files = [path for path in probes.rglob("*") if "transcript.md" not in path.relative_to(root).parts and path.is_file()]
        if not files or any(path.suffix.lower() not in {".json", ".jsonl"} for path in files):
            raise BundleError("trial III probes/ may contain JSON/JSONL I/O only, never vendor source")
        boundary = probes / "boundary-ladder.json"
        if not boundary.is_file():
            raise BundleError("trial III requires probes/boundary-ladder.json")
        for path in files:
            if path.suffix.lower() == ".json":
                data = read_json(path)
                if not isinstance(data, dict) or set(data) != {"format", "cases"} or data.get("format") != "molt-warden-probe-io/v1" or not isinstance(data.get("cases"), list) or not data["cases"]:
                    raise BundleError(f"trial III probe is not a valid I/O-only record: {path.relative_to(root)}")
                for case in data["cases"]:
                    if not isinstance(case, dict) or set(case) != {"case_id", "input", "output"} or not isinstance(case.get("case_id"), str) or not case["case_id"]:
                        raise BundleError(f"trial III probe contains non-I/O data: {path.relative_to(root)}")
            else:
                try:
                    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
                except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                    raise BundleError(f"trial III JSONL probe is invalid: {path.relative_to(root)}: {exc}") from exc
                if not rows or any(not isinstance(row, dict) or set(row) != {"case_id", "input", "output"} or not isinstance(row.get("case_id"), str) or not row["case_id"] for row in rows):
                    raise BundleError(f"trial III JSONL probe contains non-I/O data: {path.relative_to(root)}")
        poisoned = root / "attacks" / "poisoned-variant.json"
        if not poisoned.is_file():
            raise BundleError("trial III requires attacks/poisoned-variant.json")
        for path in root.rglob("*"):
            relative = path.relative_to(root)
            if "transcript.md" in relative.parts:
                continue
            if path.is_file() and path != root / "replay.sh" and path.suffix.lower() in SOURCE_SUFFIXES:
                raise BundleError(f"trial III contains source code, not black-box probe I/O: {relative}")
        if (root / "vendors").exists() or (root / "vendor-source").exists():
            raise BundleError("trial III bundles must not contain vendor source")
    if trial == "IV":
        delegation = root / "keys" / "delegation.json"
        if not delegation.is_file():
            raise BundleError("trial IV requires keys/delegation.json with the full genesis-to-current chain")


def _check_point_in_time(root: Path, manifest: dict) -> None:
    pit = manifest.get("point_in_time")
    if pit is None:
        return
    if not isinstance(pit, dict):
        raise BundleError("point_in_time must be an object")
    required = ("anchor_tick", "anchor_event_id", "session_id", "triggering_alert_id")
    for key in required:
        if key not in pit:
            raise BundleError(f"point_in_time missing key: {key}")
    anchor_tick = pit["anchor_tick"]
    if type(anchor_tick) is not int or anchor_tick < 0:
        raise BundleError("point_in_time.anchor_tick must be a non-negative integer")
    for key in ("anchor_event_id", "session_id", "triggering_alert_id"):
        value = pit[key]
        if not isinstance(value, str) or not value or len(value) > 200:
            raise BundleError(f"point_in_time.{key} must be a non-empty string of at most 200 characters")

    found_anchor = False
    stores = root / "stores"
    for event_file in stores.rglob("*.jsonl"):
        try:
            lines = event_file.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise BundleError(f"point_in_time cannot read {event_file.relative_to(root)}: {exc}") from exc
        for line_no, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(
                    line,
                    object_pairs_hook=_pairs_no_duplicates,
                    parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"invalid JSON constant: {value}")),
                )
            except (json.JSONDecodeError, ValueError) as exc:
                raise BundleError(f"point_in_time invalid JSON in {event_file.relative_to(root)}:{line_no}: {exc}") from exc
            if not isinstance(event, dict):
                raise BundleError(f"point_in_time event must be an object in {event_file.relative_to(root)}:{line_no}")
            event_id = event.get("id", event.get("event_id"))
            if event_id == pit["anchor_event_id"]:
                found_anchor = True
            if "tick" in event:
                tick = event["tick"]
                if type(tick) is not int or tick < 0:
                    raise BundleError(f"point_in_time event tick must be a non-negative integer in {event_file.relative_to(root)}:{line_no}")
                if tick > anchor_tick:
                    raise BundleError(
                        f"event past point_in_time anchor in {event_file.relative_to(root)}: "
                        f"tick {tick} > {anchor_tick}"
                    )
    if not found_anchor:
        raise BundleError("point_in_time.anchor_event_id does not exist in stores/ JSONL events")


def load_bundle(root: str | os.PathLike) -> Bundle:
    candidate = Path(root).expanduser()
    try:
        root_mode = candidate.lstat().st_mode
    except OSError as exc:
        raise BundleError(f"bundle path unavailable: {exc}") from exc
    if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode):
        raise BundleError(f"bundle root must be a real directory, not a symlink: {candidate}")
    root_path = candidate.resolve(strict=True)
    _inventory(root_path)
    for name in REQUIRED:
        entry = root_path / name
        if not entry.exists():
            raise BundleError(f"missing required entry: {name}")
        if name in {"anchors", "stores", "keys", "artifacts"} and not entry.is_dir():
            raise BundleError(f"required entry must be a directory: {name}")
        if name in {"manifest.json", "replay.sh"} and not entry.is_file():
            raise BundleError(f"required entry must be a regular file: {name}")
    manifest_path = root_path / "manifest.json"
    try:
        manifest = read_json(manifest_path)
    except BundleError as exc:
        raise BundleError(f"manifest.json unparseable: {exc}") from exc
    if not isinstance(manifest, dict):
        raise BundleError("manifest.json root must be an object")
    for key in ("bundle_id", "trial", "fixture", "claimed_state_root"):
        if key not in manifest:
            raise BundleError(f"manifest missing key: {key}")
    if not isinstance(manifest["bundle_id"], str) or not manifest["bundle_id"] or len(manifest["bundle_id"]) > 200:
        raise BundleError("manifest bundle_id must be a non-empty string of at most 200 characters")
    trial = manifest["trial"]
    if trial not in TRIAL_FIXTURE:
        raise BundleError(f"bad trial: {trial}")
    if manifest["fixture"] != TRIAL_FIXTURE[trial]:
        raise BundleError(f"trial {trial} requires fixture {TRIAL_FIXTURE[trial]}")
    claimed = manifest["claimed_state_root"]
    if not isinstance(claimed, str) or not ROOT_HASH.fullmatch(claimed):
        raise BundleError(f"malformed claimed_state_root: {claimed!r}")
    claimed_criteria = manifest.get("claimed_criteria", [])
    if not isinstance(claimed_criteria, list) or any(not isinstance(item, str) for item in claimed_criteria):
        raise BundleError("manifest claimed_criteria must be an array of strings")
    toolchain = manifest.get("toolchain", {})
    if not isinstance(toolchain, dict):
        raise BundleError("manifest toolchain must be an object")
    if not (root_path / "replay.sh").stat().st_mode & stat.S_IXUSR:
        raise BundleError("replay.sh must be executable (owner execute bit required)")
    bundle = Bundle(root=root_path, manifest=manifest)
    if bundle.state_root() != claimed:
        raise BundleError("manifest claimed_state_root does not equal artifacts/state_root.txt")
    _check_point_in_time(root_path, manifest)
    _check_keys(root_path)
    _check_trial_specific(root_path, trial)
    return bundle
