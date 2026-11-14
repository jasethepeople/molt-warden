"""Verdict model. The grader's only serialized output surface."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Literal

Status = Literal["PASS", "FAIL", "VOID", "SKIP"]


@dataclass
class Result:
    id: str
    status: Status
    reason: str = ""


@dataclass
class Replay:
    status: Status
    state_root: str = ""
    duration_s: float = 0.0
    reason: str = ""


@dataclass
class Verdict:
    warden_version: str
    grader_commit: str
    bundle_id: str
    trial: str
    fixture: str
    replay: Replay
    criteria: list[Result] = field(default_factory=list)
    invariants: list[Result] = field(default_factory=list)
    overall: Status = "VOID"

    def finalize(self) -> "Verdict":
        if any(result.status == "FAIL" for result in self.invariants):
            self.overall = "VOID"
        elif self.replay.status != "PASS":
            self.overall = "VOID"
        elif all(result.status == "PASS" for result in self.criteria) and all(result.status == "PASS" for result in self.invariants):
            self.overall = "PASS"
        else:
            self.overall = "FAIL"
        return self

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True, ensure_ascii=False)

    @classmethod
    def from_json(cls, source: str) -> "Verdict":
        data = json.loads(source)
        return cls(
            warden_version=data["warden_version"],
            grader_commit=data["grader_commit"],
            bundle_id=data["bundle_id"],
            trial=data["trial"],
            fixture=data["fixture"],
            replay=Replay(**data["replay"]),
            criteria=[Result(**item) for item in data["criteria"]],
            invariants=[Result(**item) for item in data["invariants"]],
            overall=data["overall"],
        )
