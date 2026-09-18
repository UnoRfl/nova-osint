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
from typing import TYPE_CHECKING, Any

# Safe to import outright: acquisition.py imports nothing from this package,
# precisely so that the provenance record can be attached at any layer.
from .acquisition import Acquisition

if TYPE_CHECKING:  # pragma: no cover - import cycle: entities needs TargetType
    from .entities import Entity, EntityType


class TargetType(str, Enum):
    USERNAME = "username"
    #: A human name. Deliberately separate from USERNAME: a handle identifies
    #: one account, a name identifies a set of people, and treating the second
    #: like the first is how these tools produce confident nonsense.
    PERSON = "person"
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
    #: A source will answer, but only to a person: a login wall, a consent
    #: interstitial, a CAPTCHA. Its own status rather than BLOCKED, because
    #: BLOCKED means "we are not allowed and will not work around it" and this
    #: means "you can finish this yourself in ten seconds". NOVA never solves
    #: one; it names the URL and stops.
    HUMAN_ACTION = "human action required"

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
    #: How this value was obtained, as opposed to who said it. Optional so
    #: every existing construction site keeps working; a renderer that finds
    #: it missing says "method not recorded" rather than guessing one.
    acquisition: Acquisition | None = None
    #: When the *source* observed this, if it said. Distinct from the moment
    #: we fetched it (``acquisition.obtained_at``): a profile fetched today can
    #: be asserting something it last checked in 2019, and a timeline that
    #: conflates the two dates is a timeline of our own scanning.
    observed_at: float | None = None

    @property
    def method(self) -> str:
        """One word for how this arrived, for renderers that show a column."""
        return self.acquisition.method.value if self.acquisition else "unrecorded"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["acquisition"] = self.acquisition.to_dict() if self.acquisition else None
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
class Link:
    """An edge a module wants drawn on the investigation graph.

    Deliberately a plain record rather than a ``graph.Edge``: modules produce
    these, the engine turns them into weighted edges. Keeping the conversion on
    the engine's side means a module never has to know about log-odds, hub
    demotion or the evidence table - it says *what it saw*, and the scoring
    layer decides what that is worth.
    """

    src: Entity
    dst: Entity
    label: str
    #: Key into :data:`nova_osint.core.graph.EVIDENCE`.
    kind: str
    module: str = ""
    url: str | None = None
    detail: str = ""
    #: sha256 of the stored response this was read from, when available.
    evidence: str | None = None
    #: Explicit strength, when the module can be more precise than the table.
    llr: float | None = None


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
    #: The entity this module was pointed at. Set by the engine before ``run``,
    #: so ``result.entity(...)`` knows what to hang a discovery off.
    subject: Entity | None = None
    #: Entities discovered, and the edges connecting them. Merged into the
    #: investigation graph by the engine once the module returns.
    nodes: list[Entity] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)

    def add(self, label: str, value: Any, source: str, **kw: Any) -> Finding:
        f = Finding(label=label, value=value, source=source, **kw)
        self.findings.append(f)
        return f

    def pivot(self, target: str, target_type: TargetType, reason: str) -> None:
        if not any(p.target == target and p.target_type == target_type for p in self.pivots):
            self.pivots.append(Pivot(target, target_type, reason))

    # -- graph ---------------------------------------------------------------

    def entity(self, etype: EntityType | str, value: Any, *, relation: str,
               evidence: str, url: str | None = None, detail: str = "",
               llr: float | None = None, **attrs: Any) -> Entity | None:
        """Record a discovery and connect it to what this module was scanning.

        The common case by far, so it is one call: "I found this thing, here is
        what it is, here is how it relates to the target, and here is the kind
        of evidence that says so". Returns the entity, or ``None`` when the
        value would not canonicalise - a miss on scraped text is normal, so the
        caller can ignore the return without a try block.
        """
        from .entities import Entity, EntityType  # local: entities needs TargetType

        etype = EntityType(etype) if isinstance(etype, str) else etype
        found = Entity.make(etype, value, **attrs)
        if found is None:
            return None
        self.nodes.append(found)
        if self.subject is not None and found.eid != self.subject.eid:
            self.link(self.subject, found, relation, evidence,
                      url=url, detail=detail, llr=llr)
        # Also record it the old way when it is something a user could scan.
        # The report's pivot section and --pivot both read Pivot objects, and a
        # module migrating to entity() should not silently empty them.
        from .entities import TO_TARGET_TYPE

        ttype = TO_TARGET_TYPE.get(found.etype)
        if ttype is not None:
            self.pivot(found.display, ttype, detail or relation)
        return found

    def link(self, src: Entity, dst: Entity, relation: str, evidence: str, *,
             url: str | None = None, detail: str = "",
             llr: float | None = None) -> None:
        """Connect two entities that are not necessarily the scan's subject."""
        self.links.append(Link(src=src, dst=dst, label=relation, kind=evidence,
                               module=self.module, url=url, detail=detail, llr=llr))

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
    #: The entity graph built during the run, when the engine was asked to
    #: expand. ``Any`` rather than ``EntityGraph`` only to keep this module free
    #: of the import cycle; it is always an ``EntityGraph`` or ``None``.
    graph: Any = None
    #: One row per HTTP request the scan made, for the case store's provenance
    #: record. Empty unless the engine was told to keep a ledger.
    requests: list[dict[str, Any]] = field(default_factory=list)
    #: An ``engine.Expansion`` when the run walked the frontier, else ``None``.
    #: Carries which budget limit stopped the walk and what was left unexplored.
    expansion: Any = None
    #: A ``brief.Brief`` when the run was given one: everything the user already
    #: knew about the subject, which seeds the scan and then discriminates
    #: between what it finds. ``Any`` to keep this module import-cycle free.
    brief: Any = None
    #: An ``identity.Resolution`` - the candidates ranked against that brief.
    #: Only ever set when ``brief`` is, because with one seed there is nothing
    #: to resolve against and a ranking would be invented rather than computed.
    resolution: Any = None
    #: ``{provider: state}`` from a ``providers.ProviderHealth`` snapshot: what
    #: each external source did during this run. Modules report per-module
    #: status; this reports per-*source*, which is the level at which "it was
    #: rate limited" and "it costs money" are true.
    providers: dict[str, Any] = field(default_factory=dict)
    #: ``router.Outcome`` dicts for needs that were routed rather than scanned.
    #: The record of which rung of the free-first ladder answered, and what
    #: happened on the ones above it.
    routes: list[dict[str, Any]] = field(default_factory=list)

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
        """What to scan next - which never includes what was just scanned.

        A domain is a SAN on its own certificate and an MX for its own mail, so
        the target kept turning up in its own "scan these next" list. Harmless
        in isolation, but ``--pivot`` follows this list, and following it back
        to the seed spends a whole pivot budget re-running the scan that
        produced it.
        """
        self_key = self.target.strip().casefold()
        seen: dict[tuple[str, str], Pivot] = {}
        for r in self.results:
            for p in r.pivots:
                if p.target.strip().casefold() == self_key:
                    continue
                seen.setdefault((p.target, p.target_type.value), p)
        return list(seen.values())

    @property
    def incomplete(self) -> list[ScanResult]:
        """Results whose module did not get a clean run - the report needs these."""
        return [r for r in self.results if not r.status.is_complete]

    def to_dict(self) -> dict[str, Any]:
        summary = {
            "modules_run": len(self.results),
            "findings": len(self.findings),
            "pivots": len(self.pivots),
            "errors": sum(len(r.errors) for r in self.results),
            "incomplete": len(self.incomplete),
            "skipped": len(self.skipped),
        }
        if self.graph is not None:
            summary["entities"] = len(self.graph)
            summary["edges"] = len(self.graph.edges)
        out: dict[str, Any] = {
            "target": self.target,
            "target_type": self.target_type.value,
            "started_at": self.started_at,
            "duration": round(self.duration, 2),
            "summary": summary,
            "module_status": {r.module: r.status.value for r in self.results},
            "skipped": [{"module": name, "reason": reason} for name, reason in self.skipped],
            "results": [r.to_dict() for r in self.results],
            "pivots": [p.to_dict() for p in self.pivots],
        }
        if self.graph is not None:
            out["graph"] = self.graph.to_dict()
        if self.expansion is not None:
            out["expansion"] = self.expansion.to_dict()
        if self.brief is not None:
            out["brief"] = self.brief.to_dict()
        if self.resolution is not None:
            out["resolution"] = self.resolution.to_dict()
        if self.providers:
            out["providers"] = self.providers
        if self.routes:
            out["routes"] = self.routes
        return out
