"""Sealed, double-run replay gate with host-owned Docker telemetry."""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .bundle import Bundle, BundleError, MAX_BUNDLE_BYTES, MAX_FILES
from .fixtures import FixtureError, verify_fixture

REPLAY_IMAGE = "warden-replay:v0"
REPLAY_BUDGET_S = 900
REPLAY_MEMORY = 512 * 1024 * 1024
REPLAY_NANO_CPUS = 2_000_000_000
REPLAY_PIDS = 256
SAMPLE_INTERVAL_S = 0.2
ROOT_LINE = re.compile(rb"state_root sha256:[0-9a-f]{64}\Z")
MAX_CAPTURE = 12 * 1024 * 1024


@dataclass
class ReplayOutcome:
    ok: bool
    state_root: str
    duration_s: float
    reason: str
    runs: list[dict] = field(default_factory=list)
    attack_runs: list[dict] = field(default_factory=list)


def _docker_env() -> dict[str, str]:
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "TZ": "UTC"}


def _check_tree(source: Path, ignore_transcript: bool = False) -> tuple[int, int]:
    if source.is_symlink() or not source.is_dir():
        raise BundleError(f"replay input is not a real directory: {source}")
    count = 0
    total = 0
    for current, dirs, files in os.walk(source, topdown=True, followlinks=False):
        base = Path(current)
        if ignore_transcript and "transcript.md" in dirs:
            dirs.remove("transcript.md")
        for name in dirs:
            path = base / name
            if path.is_symlink() or not path.is_dir():
                raise BundleError(f"symlink or non-directory in replay input: {path}")
            count += 1
        for name in files:
            if ignore_transcript and name == "transcript.md":
                continue
            path = base / name
            metadata = path.stat(follow_symlinks=False)
            mode = metadata.st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISREG(mode) or metadata.st_nlink > 1:
                raise BundleError(f"symlink, hardlink, or special file in replay input: {path}")
            count += 1
            total += metadata.st_size
            if count > MAX_FILES or total > MAX_BUNDLE_BYTES:
                raise BundleError("replay inputs exceed file-count or size limit")
    return count, total


def _stage(source: Path, dest: Path, ignore_transcript: bool = False) -> None:
    _check_tree(source, ignore_transcript=ignore_transcript)
    def ignore(directory: str, names: list[str]) -> set[str]:
        if not ignore_transcript:
            return set()
        relative = Path(directory).relative_to(source)
        if "transcript.md" in relative.parts:
            return set(names)
        return {name for name in names if name == "transcript.md"}
    shutil.copytree(source, dest, symlinks=True, ignore=ignore if ignore_transcript else None)
    _check_tree(dest)
    for current, dirs, files in os.walk(dest, topdown=False):
        base = Path(current)
        for name in files:
            path = base / name
            relative = path.relative_to(dest)
            executable = relative.as_posix() == "replay.sh" or (relative.parts[0] == "attacks" and path.suffix.lower() == ".sh")
            path.chmod(0o555 if executable else 0o444)
        for name in dirs:
            (base / name).chmod(0o555)
    dest.chmod(0o555)


def _read_capture(file_obj, max_bytes: int) -> bytes:
    file_obj.seek(0)
    data = file_obj.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("container output exceeded the grader's capture limit")
    return data


def _docker_call(docker: str, *args: str, timeout: float = 5.0) -> subprocess.CompletedProcess:
    return subprocess.run([docker, *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=max(0.2, timeout), check=False,
                          env=_docker_env(), close_fds=True)


def _parse_size(text: str) -> int | None:
    match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]+)\s*", text)
    if not match:
        return None
    unit = match.group(2)
    factors = {"B": 1, "kB": 1000, "MB": 1000**2, "GB": 1000**3, "TB": 1000**4,
               "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4}
    return int(float(match.group(1)) * factors[unit]) if unit in factors else None


def _parse_process_table(text: str) -> list[dict]:
    lines = text.splitlines()
    if len(lines) < 2:
        return []
    rows = []
    for line in lines[1:]:
        fields = line.strip().split(None, 2)
        if len(fields) != 3:
            continue
        try:
            pid, ppid = int(fields[0]), int(fields[1])
        except ValueError:
            continue
        rows.append({"pid": pid, "ppid": ppid, "command": fields[2][:2048]})
    return rows


def _audit_processes(snapshots: list[list[dict]], script: str = "/bundle/replay.sh") -> dict:
    runner_seen = False
    trial_seen = False
    unattributed = False
    processes = {}
    for rows in snapshots:
        runners = [row for row in rows if "/opt/warden/runner.py" in row["command"]]
        if len(runners) == 1:
            runner_seen = True
            root_pid = runners[0]["pid"]
            active = {root_pid}
            changed = True
            while changed:
                changed = False
                for row in rows:
                    if row["pid"] not in active and row["ppid"] in active:
                        active.add(row["pid"])
                        changed = True
            for row in rows:
                processes[(row["pid"], row["command"])] = row
                if row["pid"] == root_pid:
                    continue
                if row["pid"] in active and script in row["command"]:
                    trial_seen = True
                if row["pid"] not in active:
                    unattributed = True
        elif rows:
            unattributed = True
            for row in rows:
                processes[(row["pid"], row["command"])] = row
    return {
        "process_samples": len(snapshots),
        "runner_seen": runner_seen,
        "trial_process_seen": trial_seen,
        "unattributed_process": unattributed,
        "process_tree": sorted(processes.values(), key=lambda item: (item["pid"], item["command"])),
    }


def _inspect(docker: str, name: str, timeout: float) -> dict | None:
    result = _docker_call(docker, "inspect", "--format", "{{json .}}", name, timeout=timeout)
    if result.returncode:
        return None
    try:
        data = json.loads(result.stdout)
        return data if isinstance(data, dict) else None
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _sample_resources(docker: str, name: str, timeout: float) -> dict | None:
    result = _docker_call(docker, "stats", "--no-stream", "--format", "{{json .}}", name, timeout=timeout)
    if result.returncode:
        return None
    try:
        data = json.loads(result.stdout)
        usage = data.get("MemUsage", "").split("/", 1)[0].strip()
        cpu = float(str(data.get("CPUPerc", "")).strip().removesuffix("%"))
        memory = _parse_size(usage)
        pids = int(data.get("PIDs", ""))
        if memory is None:
            return None
        if not math.isfinite(cpu) or cpu < 0 or pids < 0:
            return None
        return {"memory_bytes": memory, "cpu_percent": cpu, "pids": pids}
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, TypeError, AttributeError):
        return None


def _sample_processes(docker: str, name: str, timeout: float) -> list[dict] | None:
    result = _docker_call(docker, "top", name, "-eo", "pid,ppid,args", timeout=timeout)
    if result.returncode:
        return None
    return _parse_process_table(result.stdout.decode("utf-8", "replace"))


def _inspect_metrics(container: dict | None) -> dict:
    if not container:
        return {}
    state = container.get("State", {})
    config = container.get("HostConfig", {})
    return {
        "oom_killed": state.get("OOMKilled"),
        "container_exit_code": state.get("ExitCode"),
        "container_status": state.get("Status"),
        "memory_limit_bytes": config.get("Memory"),
        "nano_cpus": config.get("NanoCpus"),
        "pids_limit": config.get("PidsLimit"),
    }


def _run_once(docker: str, bundle_dir: Path, fixture_dir: Path, timeout_s: float, script: str = "/bundle/replay.sh", image_ref: str = REPLAY_IMAGE) -> tuple[int | None, bytes, bytes, float, str, dict]:
    name = "warden-" + uuid.uuid4().hex
    command = [
        docker, "create", "--name", name, "--network=none", "--ipc=private", "--hostname=molt-warden", "--read-only",
        "--security-opt=no-new-privileges", "--cap-drop=ALL", "--pids-limit", str(REPLAY_PIDS),
        "--memory", str(REPLAY_MEMORY), "--memory-swap", str(REPLAY_MEMORY),
        "--cpus", "2", "--user", "65534:65534", "--workdir", "/bundle",
        "--ulimit", "nofile=256:256", "--ulimit", "nproc=256:256", "--ulimit", "core=0:0",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m,uid=65534,gid=65534",
        "--env", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "--env", "LANG=C.UTF-8", "--env", "TZ=UTC",
        "--mount", f"type=bind,src={bundle_dir},dst=/bundle,readonly",
        "--mount", f"type=bind,src={fixture_dir},dst=/fixtures,readonly",
        image_ref, script,
    ]
    started = time.monotonic()
    container_id = None
    stdout_file = tempfile.TemporaryFile()
    stderr_file = tempfile.TemporaryFile()
    snapshots: list[list[dict]] = []
    resources: list[dict] = []
    proc = None
    reason = ""
    exit_code: int | None = None
    output = error = b""
    inspection = None
    try:
        created = _docker_call(docker, *command[1:], timeout=min(20.0, timeout_s))
        if created.returncode:
            detail = created.stderr.decode("utf-8", "replace")[-2000:].strip()
            return None, b"", b"", time.monotonic() - started, f"Docker could not create isolated container: {detail}", {}
        container_id = created.stdout.decode("ascii", "replace").strip()
        if not container_id:
            return None, b"", b"", time.monotonic() - started, "Docker returned no container ID", {}
        try:
            proc = subprocess.Popen([docker, "start", "--attach", container_id], stdin=subprocess.DEVNULL,
                                    stdout=stdout_file, stderr=stderr_file, env=_docker_env(), close_fds=True)
        except OSError as exc:
            return None, b"", b"", time.monotonic() - started, f"could not attach to replay container: {exc}", {}

        deadline = started + timeout_s
        while proc.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reason = "wall-clock budget exceeded (900s total for both runs)"
                _docker_call(docker, "kill", container_id, timeout=3)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
                break
            sample = _sample_resources(docker, container_id, min(5.0, remaining))
            if sample:
                resources.append(sample)
            process_table = _sample_processes(docker, container_id, min(5.0, remaining))
            if process_table:
                snapshots.append(process_table)
            time.sleep(min(SAMPLE_INTERVAL_S, max(0.0, deadline - time.monotonic())))
        if not reason:
            exit_code = proc.returncode
        inspection = _inspect(docker, container_id, timeout=min(5.0, max(0.2, timeout_s)))
        if inspection:
            state_code = inspection.get("State", {}).get("ExitCode")
            if type(state_code) is int:
                exit_code = state_code
        stdout_file.seek(0)
        stderr_file.seek(0)
        try:
            output = _read_capture(stdout_file, MAX_CAPTURE)
            error = _read_capture(stderr_file, MAX_CAPTURE)
        except ValueError as exc:
            reason = str(exc)
        runtime = _audit_processes(snapshots, script)
        runtime.update(_inspect_metrics(inspection))
        runtime["resource_samples"] = resources
        runtime["host_sample_source"] = "docker-stats-and-inspect"
        duration = time.monotonic() - started
        if reason:
            return exit_code, output, error, duration, reason, runtime
        if inspection is None:
            return exit_code, output, error, duration, "Docker daemon did not provide final host inspection data", runtime
        if exit_code != 0:
            detail = error.decode("utf-8", "replace")[-3000:].strip()
            return exit_code, output, error, duration, f"container exited {exit_code}: {detail or 'no diagnostic'}", runtime
        return exit_code, output, error, duration, "", runtime
    except (OSError, subprocess.TimeoutExpired) as exc:
        return exit_code, output, error, time.monotonic() - started, f"Docker host observation failed: {exc}", {}
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
        if container_id:
            _docker_call(docker, "rm", "--force", container_id, timeout=5)
        stdout_file.close()
        stderr_file.close()


def _last_root(stdout: bytes) -> str | None:
    lines = stdout.splitlines()
    if not lines:
        return None
    last = lines[-1].strip()
    if not ROOT_LINE.fullmatch(last):
        return None
    return last.decode("ascii").removeprefix("state_root ")


def _pinned_image(docker: str, project_root: Path) -> tuple[str | None, str]:
    pin_file = project_root / "docker" / "image-id.txt"
    try:
        expected = pin_file.read_text(encoding="ascii").strip()
    except OSError:
        return None, "local replay image is not pinned; run `python -m moltwarden replay-image build`"
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected):
        return None, "docker/image-id.txt is malformed; rebuild the replay image"
    try:
        result = subprocess.run([docker, "image", "inspect", "--format", "{{.Id}}", REPLAY_IMAGE],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=15, check=False, env=_docker_env(), close_fds=True)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"Docker daemon/image check failed: {exc}"
    actual = result.stdout.decode("ascii", "replace").strip()
    if result.returncode or actual != expected:
        return None, f"required replay image is missing or differs from pinned image ID {expected}"
    return actual, ""


def run_replay(bundle: Bundle, fixtures_dir: str) -> ReplayOutcome:
    started = time.monotonic()
    docker = shutil.which("docker")
    if not docker:
        return ReplayOutcome(False, "", 0.0, "Docker CLI is unavailable; replay cannot be run safely")
    project_root = Path(__file__).resolve().parent.parent
    image_ref, pin_reason = _pinned_image(docker, project_root)
    if image_ref is None:
        return ReplayOutcome(False, "", 0.0, pin_reason)
    fixture = Path(fixtures_dir).expanduser()
    expected = bundle.state_root()
    if bundle.manifest["claimed_state_root"] != expected:
        return ReplayOutcome(False, "", 0.0, "manifest root differs from artifacts/state_root.txt")
    fixture_name = bundle.manifest["fixture"]
    fixture_source = fixture / fixture_name
    try:
        _check_tree(fixture_source)
        verify_fixture(fixture_source, fixture_name)
    except (BundleError, FixtureError, OSError, ValueError) as exc:
        return ReplayOutcome(False, "", 0.0, f"unsafe, missing, oversized, or noncanonical fixture input: {exc}")

    roots = []
    logs = []
    attack_logs = []
    try:
        with tempfile.TemporaryDirectory(prefix="molt-warden-") as temporary:
            temp = Path(temporary)
            staged_bundle = temp / "bundle"
            staged_fixtures = temp / "fixtures"
            _stage(bundle.root, staged_bundle, ignore_transcript=True)
            _stage(fixture_source, staged_fixtures)
            verify_fixture(staged_fixtures, fixture_name)
            deadline = started + REPLAY_BUDGET_S
            attack_script = None
            if bundle.trial in {"II", "IV"}:
                scripts = sorted(path for path in bundle.root.joinpath("attacks").rglob("*")
                                 if path.is_file() and path.suffix.lower() in {".sh", ".py"})
                if len(scripts) != 1:
                    return ReplayOutcome(False, "", time.monotonic() - started, "attacks/: exactly one deterministic agent-authored .sh or .py script is required", logs, attack_logs)
                attack_script = "/bundle/" + scripts[0].relative_to(bundle.root).as_posix()
                for index in (1, 2):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return ReplayOutcome(False, "", time.monotonic() - started, "wall-clock budget exceeded (900s total)", logs, attack_logs)
                    code, _, _, duration, reason, runtime = _run_once(docker, staged_bundle, staged_fixtures, remaining, attack_script, image_ref)
                    attack_logs.append({"run": index, "exit_code": code, "duration_s": round(duration, 6), "runtime": runtime})
                    if code != 0:
                        return ReplayOutcome(False, "", time.monotonic() - started, f"attack rerun {index}: {reason or 'nonzero exit'}", logs, attack_logs)
            for index in (1, 2):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return ReplayOutcome(False, "", time.monotonic() - started, "wall-clock budget exceeded (900s total)", logs, attack_logs)
                code, stdout, _, duration, reason, runtime = _run_once(docker, staged_bundle, staged_fixtures, remaining, image_ref=image_ref)
                state_root = _last_root(stdout) if code == 0 else None
                logs.append({"run": index, "exit_code": code, "duration_s": round(duration, 6), "state_root": state_root, "runtime": runtime})
                if code != 0:
                    return ReplayOutcome(False, state_root or "", time.monotonic() - started, f"run {index}: {reason or 'nonzero exit'}", logs, attack_logs)
                if state_root is None:
                    return ReplayOutcome(False, "", time.monotonic() - started, f"run {index}: stdout final line is not `state_root sha256:<64 lowercase hex>`", logs, attack_logs)
                if state_root != expected:
                    return ReplayOutcome(False, state_root, time.monotonic() - started, f"run {index}: replay root differs from artifacts/state_root.txt", logs, attack_logs)
                roots.append(state_root)
            if roots[0] != roots[1]:
                return ReplayOutcome(False, roots[-1], time.monotonic() - started, "the two replay runs produced different roots", logs, attack_logs)
    except (BundleError, OSError, shutil.Error) as exc:
        return ReplayOutcome(False, "", time.monotonic() - started, f"unsafe or unreadable replay input: {exc}", logs, attack_logs)
    return ReplayOutcome(True, roots[0], time.monotonic() - started, "two sealed replay runs and any required attack reruns matched", logs, attack_logs)
