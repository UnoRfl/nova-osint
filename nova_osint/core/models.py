"""Data model shared by every module.

A scan produces one ``ScanResult`` per module. Each result carries zero or more
``Finding`` objects (the facts) and zero or more ``Pivot`` objects (new targets
worth scanning next). Everything is JSON-serialisable so reports and the API
surface stay trivial.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class TargetType(str, Enum):
    USERNAME = "username"
    EMAIL = "email"
    DOMAIN = "domain"
    IP = "ip"
    PHONE = "phone"
    URL = "url"
    UNKNOWN = "unknown"


class Confidence(str, Enum):
    """How much weight to put on a finding.

    CONFIRMED  the source is authoritative (RDAP registry, DNS, GitHub API)
    LIKELY     a strong but heuristic signal (profile page returned 200)
    POSSIBLE   weak or ambiguous (soft-404 suspected, fuzzy name match)
    """

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"


class Severity(str, Enum):
    """Investigative interest, not vulnerability severity."""

    INFO = "info"
    NOTABLE = "notable"
    HIGH = "high"


@dataclass
class Finding:
    label: str
    value: Any
    source: str
    confidence: Confidence = Confidence.CONFIRMED
    severity: Severity = Severity.INFO
    url: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["confidence"] = self.confidence.value
        d["severity"] = self.severity.value
        return d


@dataclass
class Pivot:
    """A new target discovered mid-scan that the user may want to follow."""

    target: str
    target_type: TargetType
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type.value,
            "reason": self.reason,
        }


@dataclass
class ScanResult:
    module: str
    target: str
    target_type: TargetType
    findings: list[Finding] = field(default_factory=list)
    pivots: list[Pivot] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    duration: float = 0.0

    def add(self, label: str, value: Any, source: str, **kw: Any) -> Finding:
        f = Finding(label=label, value=value, source=source, **kw)
        self.findings.append(f)
        return f

    def pivot(self, target: str, target_type: TargetType, reason: str) -> None:
        if not any(p.target == target and p.target_type == target_type for p in self.pivots):
            self.pivots.append(Pivot(target, target_type, reason))

    def error(self, message: str) -> None:
        self.errors.append(message)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "target": self.target,
            "target_type": self.target_type.value,
            "findings": [f.to_dict() for f in self.findings],
            "pivots": [p.to_dict() for p in self.pivots],
            "errors": self.errors,
            "duration": round(self.duration, 2),
        }


@dataclass
class Investigation:
    """The whole scan: one target, many module results."""

    target: str
    target_type: TargetType
    results: list[ScanResult] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)

    @property
    def findings(self) -> list[Finding]:
        return [f for r in self.results for f in r.findings]

    @property
    def pivots(self) -> list[Pivot]:
        seen: dict[tuple[str, str], Pivot] = {}
        for r in self.results:
            for p in r.pivots:
                seen.setdefault((p.target, p.target_type.value), p)
        return list(seen.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type.value,
            "started_at": self.started_at,
            "duration": round(time.time() - self.started_at, 2),
            "summary": {
                "modules_run": len(self.results),
                "findings": len(self.findings),
                "pivots": len(self.pivots),
                "errors": sum(len(r.errors) for r in self.results),
            },
            "results": [r.to_dict() for r in self.results],
            "pivots": [p.to_dict() for p in self.pivots],
        }
