"""Data model shared by every module.

A scan produces one ``ScanResult`` per module. Each result carries zero or more
``Finding`` objects (the facts), zero or more ``Pivot`` objects (new targets
worth scanning next), and a ``ModuleStatus`` saying whether the module actually
got to do its job. Everything is JSON-serialisable so reports and the API
surface stay trivial.

The status matters more than it looks. "The username module returned nothing"
and "the username module was rate limited after nine sites" produce the same
empty findings list and mean completely different things; without a status the
report quietly presents the second as the first.
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


class ModuleStatus(str, Enum):
    """Did this module finish, and if not, why not?

    SUCCESS       ran to completion and found something
    EMPTY         ran to completion and found nothing (a real answer)
    PARTIAL       ran, but some of its sources failed
    RATE_LIMITED  a source asked us to slow down and we stopped rather than push
    BLOCKED       a source refused us (403/451); we do not work around that
    UNAVAILABLE   a source was unreachable or erroring
    FAILED        the module itself raised
    SKIPPED       never ran (no API key, passive mode, disabled in config)
    """

    SUCCESS = "success"
    EMPTY = "empty"
    PARTIAL = "partial"
    RATE_LIMITED = "rate limited"
    BLOCKED = "blocked"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"
    SKIPPED = "skipped"

    @property
    def is_complete(self) -> bool:
        return self in (ModuleStatus.SUCCESS, ModuleStatus.EMPTY)


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
    status: ModuleStatus = ModuleStatus.SUCCESS
    #: Human sentence explaining a non-success status, shown in the report.
    status_reason: str = ""

    def add(self, label: str, value: Any, source: str, **kw: Any) -> Finding:
        f = Finding(label=label, value=value, source=source, **kw)
        self.findings.append(f)
        return f

    def pivot(self, target: str, target_type: TargetType, reason: str) -> None:
        if not any(p.target == target and p.target_type == target_type for p in self.pivots):
            self.pivots.append(Pivot(target, target_type, reason))

    def error(self, message: str) -> None:
        self.errors.append(message)

    def degrade(self, status: ModuleStatus, reason: str = "") -> None:
        """Record a worse outcome, keeping the worst one seen.

        Modules call this when a source refuses; the engine calls it when a
        module raises. Ordering is fixed by :data:`_STATUS_RANK` so two sources
        failing differently cannot downgrade each other.
        """
        if _STATUS_RANK[status] > _STATUS_RANK[self.status]:
            self.status = status
            self.status_reason = reason
        elif status is self.status and reason and not self.status_reason:
            self.status_reason = reason

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "target": self.target,
            "target_type": self.target_type.value,
            "status": self.status.value,
            "status_reason": self.status_reason,
            "findings": [f.to_dict() for f in self.findings],
            "pivots": [p.to_dict() for p in self.pivots],
            "errors": self.errors,
            "duration": round(self.duration, 2),
        }


#: Higher wins when two outcomes collide. SUCCESS/EMPTY are the floor; FAILED
#: is the ceiling because a crashed module is the least trustworthy result.
_STATUS_RANK = {
    ModuleStatus.SUCCESS: 0,
    ModuleStatus.EMPTY: 1,
    ModuleStatus.PARTIAL: 2,
    ModuleStatus.RATE_LIMITED: 3,
    ModuleStatus.BLOCKED: 4,
    ModuleStatus.UNAVAILABLE: 5,
    ModuleStatus.SKIPPED: 6,
    ModuleStatus.FAILED: 7,
}


@dataclass
class Investigation:
    """The whole scan: one target, many module results."""

    target: str
    target_type: TargetType
    results: list[ScanResult] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    #: Set by :meth:`finish`. Until then the duration is "so far".
    finished_at: float | None = None
    #: ``[(module name, why it did not run)]`` - reported, not silently dropped.
    skipped: list[tuple[str, str]] = field(default_factory=list)

    def finish(self) -> Investigation:
        """Freeze the clock.

        Without this the duration is recomputed on every ``to_dict()``, so a
        report rendered three times shows three different scan times - all of
        them wrong, because they include the time spent rendering.
        """
        if self.finished_at is None:
            self.finished_at = time.time()
        return self

    @property
    def duration(self) -> float:
        end = self.finished_at if self.finished_at is not None else time.time()
        return end - self.started_at

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

    @property
    def incomplete(self) -> list[ScanResult]:
        """Results whose module did not get a clean run - the report needs these."""
        return [r for r in self.results if not r.status.is_complete]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type.value,
            "started_at": self.started_at,
            "duration": round(self.duration, 2),
            "summary": {
                "modules_run": len(self.results),
                "findings": len(self.findings),
                "pivots": len(self.pivots),
                "errors": sum(len(r.errors) for r in self.results),
                "incomplete": len(self.incomplete),
                "skipped": len(self.skipped),
            },
            "module_status": {r.module: r.status.value for r in self.results},
            "skipped": [{"module": name, "reason": reason} for name, reason in self.skipped],
            "results": [r.to_dict() for r in self.results],
            "pivots": [p.to_dict() for p in self.pivots],
        }
