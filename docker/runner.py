from __future__ import annotations

import os
import signal
import stat
import subprocess
import sys
import threading
from pathlib import Path

MAX_STDOUT = 8 * 1024 * 1024
MAX_STDERR = 2 * 1024 * 1024
ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "TZ": "UTC"}


def _command(argument: str) -> list[str] | None:
    root = Path("/bundle").resolve(strict=True)
    candidate = Path(argument)
    if not candidate.is_absolute():
        return None
    try:
        resolved = candidate.resolve(strict=True)
        relative = resolved.relative_to(root)
        mode = resolved.stat().st_mode
    except (OSError, ValueError):
        return None
    if not stat.S_ISREG(mode) or candidate.is_symlink():
        return None
    parts = relative.parts
    if parts == ("replay.sh",):
        if not os.access(resolved, os.R_OK | os.X_OK):
            return None
        return [str(resolved)]
    if len(parts) != 2 or parts[0] != "attacks" or resolved.suffix.lower() not in {".sh", ".py"}:
        return None
    if resolved.suffix.lower() == ".sh":
        if not os.access(resolved, os.R_OK | os.X_OK):
            return None
        return [str(resolved)]
    if not os.access(resolved, os.R_OK):
        return None
    return ["python3", str(resolved)]


def main() -> int:
    if len(sys.argv) != 2:
        print("warden runner requires one script path", file=sys.stderr)
        return 125
    command = _command(sys.argv[1])
    if command is None:
        print("warden runner: script path is invalid or not an allowed bundle script", file=sys.stderr)
        return 125

    try:
        process = subprocess.Popen(command, cwd="/bundle", stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV,
                                   close_fds=True, start_new_session=True)
    except OSError as exc:
        print(f"warden runner: could not start bundle script: {exc}", file=sys.stderr)
        return 125
    overflow = threading.Event()
    totals = {"stdout": 0, "stderr": 0}

    def pump(stream, destination, name: str, limit: int) -> None:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            totals[name] += len(chunk)
            if totals[name] > limit:
                overflow.set()
                continue
            destination.buffer.write(chunk)
            destination.buffer.flush()

    assert process.stdout is not None and process.stderr is not None
    out_thread = threading.Thread(target=pump, args=(process.stdout, sys.stdout, "stdout", MAX_STDOUT), daemon=True)
    err_thread = threading.Thread(target=pump, args=(process.stderr, sys.stderr, "stderr", MAX_STDERR), daemon=True)
    out_thread.start()
    err_thread.start()
    while process.poll() is None:
        if overflow.is_set():
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            break
        threading.Event().wait(0.05)
    returncode = process.wait()
    out_thread.join(timeout=3)
    err_thread.join(timeout=3)
    if overflow.is_set():
        print("warden runner: stdout/stderr capture budget exceeded", file=sys.stderr)
        return 124
    if out_thread.is_alive() or err_thread.is_alive():
        print("warden runner: output streams did not close", file=sys.stderr)
        return 124
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
