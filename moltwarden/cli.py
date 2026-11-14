"""Command-line interface for verification, fixtures, red-team checks, and reports."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .bundle import BundleError
from .fixtures import build_fixtures
from .grader import grade
from .redteam import run_redteam
from .verdict import Verdict

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_VOID = 2
EXIT_ERROR = 3


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="molt-warden", description="Fail-closed MOLT sovereignty verification harness")
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="grade one submission bundle")
    verify.add_argument("bundle")
    verify.add_argument("--fixtures", default=str(Path(__file__).resolve().parent.parent / "fixtures"))
    verify.add_argument("--output", help="write verdict JSON to this path (default: stdout)")
    verify.add_argument("--grader-commit", help="override the auto-detected clean Git commit SHA")
    report = commands.add_parser("report", help="render a saved verdict")
    report.add_argument("verdict")
    fixtures = commands.add_parser("fixtures", help="materialize deterministic fixtures")
    fixture_commands = fixtures.add_subparsers(dest="fixture_command", required=True)
    build = fixture_commands.add_parser("build", help="build the v0 fixture set from checked-in seeds")
    build.add_argument("--v0", action="store_true", required=True)
    build.add_argument("--output", default=str(Path(__file__).resolve().parent.parent / "fixtures"))
    redteam = commands.add_parser("redteam", help="exercise the five frozen synthetic-cheat detectors")
    redteam.add_argument("--json", action="store_true", help="emit machine-readable results")
    image = commands.add_parser("replay-image", help="build and pin the sealed replay image")
    image_commands = image.add_subparsers(dest="image_command", required=True)
    image_commands.add_parser("build", help="build the pinned linux/amd64 replay image")
    return parser


def _write_verdict(verdict: Verdict, output: str | None) -> None:
    text = verdict.to_json()
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def _render_report(path: str) -> int:
    try:
        verdict = Verdict.from_json(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read verdict: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(f"molt-warden {verdict.warden_version} — {verdict.overall}")
    print(f"Bundle: {verdict.bundle_id} | trial {verdict.trial} | fixture {verdict.fixture}")
    print(f"Replay: {verdict.replay.status} | {verdict.replay.state_root or 'no state root'} | {verdict.replay.duration_s:.3f}s")
    if verdict.replay.reason:
        print(f"  {verdict.replay.reason}")
    for heading, results in (("Criteria", verdict.criteria), ("Invariants", verdict.invariants)):
        if results:
            print(heading + ":")
            for result in results:
                print(f"  {result.id:<5} {result.status:<4} {result.reason}")
    return EXIT_PASS if verdict.overall == "PASS" else EXIT_FAIL if verdict.overall == "FAIL" else EXIT_VOID


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "verify":
            verdict = grade(args.bundle, args.fixtures, args.grader_commit)
            _write_verdict(verdict, args.output)
            return EXIT_PASS if verdict.overall == "PASS" else EXIT_FAIL if verdict.overall == "FAIL" else EXIT_VOID
        if args.command == "report":
            return _render_report(args.verdict)
        if args.command == "fixtures":
            path = build_fixtures(args.output)
            print(path)
            return EXIT_PASS
        if args.command == "redteam":
            results = run_redteam()
            if args.json:
                print(json.dumps(results, indent=2, sort_keys=True))
            else:
                for result in results:
                    print(f"{result['cheat']} {result['status']}: {result['detail']}")
                print(f"{sum(item['status'] == 'PASS' for item in results)}/{len(results)} synthetic cheats caught")
            return EXIT_PASS if results and all(item["status"] == "PASS" for item in results) else EXIT_FAIL
        if args.command == "replay-image" and args.image_command == "build":
            import os
            import re
            import subprocess
            root = Path(__file__).resolve().parent.parent
            result = subprocess.run(
                ["docker", "build", "--pull", "--platform=linux/amd64", "-f", "docker/warden-replay.Dockerfile", "-t", "warden-replay:v0", "."],
                cwd=root, stdin=subprocess.DEVNULL, check=False,
            )
            if result.returncode:
                return EXIT_ERROR
            inspected = subprocess.run(
                ["docker", "image", "inspect", "--format", "{{.Id}}", "warden-replay:v0"],
                cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=20, check=False,
            )
            image_id = inspected.stdout.strip()
            if inspected.returncode or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
                print("ERROR: Docker did not return a valid image ID", file=sys.stderr)
                return EXIT_ERROR
            pin = root / "docker" / "image-id.txt"
            temporary = pin.with_suffix(".tmp")
            temporary.write_text(image_id + "\n", encoding="ascii")
            os.replace(temporary, pin)
            print(f"Pinned local replay image {image_id}")
            return EXIT_PASS
    except (BundleError, OSError, ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_ERROR
