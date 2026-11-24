"""Common result shape for every mail check."""
from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from typing import Any, Iterator

from app.core.target import TargetError, parse_target
from app.core.validate import ValidationError

STATUSES = ("pass", "warn", "fail", "info", "error")
FINDING_STATUSES = ("pass", "info", "warn", "fail")


@dataclass
class Finding:
    id: str
    status: str  # pass | info | warn | fail
    title: str
    meaning: str
    fix: list[str] = field(default_factory=list)
    fix_record: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if d["fix_record"] is None:
            del d["fix_record"]
        return d


@dataclass
class CheckResult:
    check: str
    target: str
    status: str = "pass"
    score: int = 100
    summary: str = ""
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    timings_ms: dict[str, float] = field(default_factory=dict)

    def add(self, id: str, status: str, title: str, meaning: str, fix: list[str] | None = None,
            fix_record: str | None = None, **details: Any) -> Finding:
        f = Finding(id, status, title, meaning, list(fix or []), fix_record, details)
        self.findings.append(f)
        return f

    def has(self, finding_id: str) -> bool:
        return any(f.id == finding_id for f in self.findings)

    def worst(self) -> str:
        sts = {f.status for f in self.findings}
        return "fail" if "fail" in sts else "warn" if "warn" in sts else "pass"

    def finalize(self, summary: str | None = None, score: int | None = None, status: str | None = None) -> "CheckResult":
        """Derive status and score from the findings unless given. Scoring: 100, minus 35 per fail and
        12 per warn (a result with any fail never scores above 65), floored at 0."""
        fails = sum(f.status == "fail" for f in self.findings)
        warns = sum(f.status == "warn" for f in self.findings)
        self.status = status or self.worst()
        if score is None:
            score = max(0, 100 - 35 * fails - 12 * warns)
            if fails:
                score = min(score, 65)
        self.score = max(0, min(100, int(score)))
        if summary is not None:
            self.summary = summary
        return self

    def to_dict(self) -> dict[str, Any]:
        return {"check": self.check, "target": self.target, "status": self.status, "score": self.score,
                "summary": self.summary, "findings": [f.to_dict() for f in self.findings],
                "data": self.data, "timings_ms": self.timings_ms}


def error_result(check: str, target: str, message: str, status: str = "error") -> CheckResult:
    r = CheckResult(check, target, status=status, score=0, summary=message)
    r.add(f"{check}_error", "fail", "The check could not be completed", message,
          ["Try again in a minute. If it keeps failing the DNS servers for this domain may be unreachable."])
    r.status = status
    r.score = 0
    return r


def clean_domain(raw: str) -> str:
    """Validate a user-supplied domain (public-looking hostname, never an IP). Raises ValidationError."""
    try:
        host, is_ip = parse_target(raw)
    except TargetError as exc:
        raise ValidationError(str(exc)) from exc
    if is_ip:
        raise ValidationError("enter a domain name, not an IP address")
    return host


@contextmanager
def timed(bucket: dict[str, float], key: str) -> Iterator[None]:
    t0 = time.perf_counter()
    try:
        yield
    finally:
        bucket[key] = round(bucket.get(key, 0.0) + (time.perf_counter() - t0) * 1000, 1)
