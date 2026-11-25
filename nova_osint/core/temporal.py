"""When things happened, in what order, and which orders are impossible.

A chronology is often the whole answer. Two accounts with the same handle are
nothing; two accounts with the same handle where the second was created the
week the first stopped posting is a lead. NOVA had the raw material for this
from the start - every ``Observation`` carries ``observed_at``, every
``Finding`` can - and did nothing with it beyond a flat list of dated labels.

Three rules this module will not bend
-------------------------------------

**The scan's own clock is not evidence.** Every duration here is measured
against ``Investigation.started_at``, never ``time.time()``. A report rendered
twice must say the same thing, a replayed case must say what it said when it
ran, and "last seen 400 days ago" must mean 400 days before the *scan*, not
before whenever somebody happened to open the file.

**A record's date is not the event's date.** ``observed_at`` is when the source
says a thing was true; ``recorded_at`` is when NOVA read it. Mixing them
produces a beautiful timeline of our own scanning. Where only the second is
available the event is marked ``precision="record"`` and excluded from conflict
detection, because "we fetched this on Tuesday" cannot contradict anything.

**A timestamp is never evidence of a place.** Commit hours have been used to
guess timezones since the first OSINT blog post, and the inference is weak
enough that :mod:`~nova_osint.core.biography` already labels it "inferred from
activity times, not stated". Nothing here upgrades that, and nothing here
derives a location from a clock at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any

from .models import Investigation

if TYPE_CHECKING:  # pragma: no cover - contradictions imports this module back
    from .contradictions import Contradiction

DAY = 86400.0

# ---------------------------------------------------------------------------
# what kind of moment this is
# ---------------------------------------------------------------------------


class EventKind(str, Enum):
    """What the date means, which is the part that makes ordering testable.

    Without this a timeline is a pile of numbers. With it, "created" coming
    after "last activity" for one subject is arithmetic rather than judgement.
    """

    CREATED = "created"
    FIRST_ACTIVITY = "first activity"
    LAST_ACTIVITY = "last activity"
    UPDATED = "updated"
    EXPIRES = "expires"
    #: A date whose meaning we could not classify. Shown, never reasoned from.
    DATED = "dated"


#: ``(kind, pattern)``, first match wins, so order matters: "last commit" has
#: to be tested before the bare "commit", and "first seen" before "seen".
_KINDS: list[tuple[EventKind, re.Pattern[str]]] = [
    (EventKind.CREATED, re.compile(
        r"creat|regist(ered|ration)|found(ed|ing)|incept|born|joined|"
        r"issued|since|opened", re.I)),
    (EventKind.EXPIRES, re.compile(r"expir|valid until|not after", re.I)),
    (EventKind.FIRST_ACTIVITY, re.compile(
        r"first (seen|commit|post|activity|release)|earliest|not before", re.I)),
    (EventKind.LAST_ACTIVITY, re.compile(
        r"last (seen|commit|post|activity|push|release|active)|latest|"
        r"most recent|pushed", re.I)),
    (EventKind.UPDATED, re.compile(r"updat|modif|changed|revised", re.I)),
]

#: A label has to look like a date before we go looking for digits in its
#: value, or every sha256 with eight leading digits joins the chronology.
_DATEY = re.compile(
    r"creat|regist|found|incept|first|last|expir|updat|push|born|issued|seen|"
    r"joined|since|date|latest|earliest|active|release|modif|valid", re.I)

_ISO = re.compile(r"\b(\d{4})-(\d{2})-(\d{2})\b")
_MONTH = re.compile(r"\b(\d{4})-(\d{2})\b")
_YEAR = re.compile(r"\b(19\d{2}|20\d{2})\b")

#: Anything outside this is a parse artefact, not a date. Certificates and
#: registries do legitimately carry dates a decade out, so the ceiling is
#: generous; the floor rules out the epoch-zero and year-0001 defaults that
#: leak out of badly-parsed records.
_FLOOR = datetime(1990, 1, 1, tzinfo=timezone.utc).timestamp()
_CEILING = datetime(2100, 1, 1, tzinfo=timezone.utc).timestamp()


def parse_date(text: str) -> tuple[float, str] | None:
    """``(unix timestamp, precision)`` for the first date in *text*, or ``None``.

    Precision is ``day``, ``month`` or ``year`` and is carried the whole way
    through, because two events an hour apart are simultaneous when one of them
    is only known to the year, and a conflict detector that forgets this
    invents impossibilities out of rounding.
    """
    if (m := _ISO.search(text)):
        y, mo, d = (int(g) for g in m.groups())
        precision = "day"
    elif (m := _MONTH.search(text)):
        y, mo, d = int(m.group(1)), int(m.group(2)), 1
        precision = "month"
    elif (m := _YEAR.search(text)):
        y, mo, d = int(m.group(1)), 1, 1
        precision = "year"
    else:
        return None
    try:
        ts = datetime(y, mo, d, tzinfo=timezone.utc).timestamp()
    except ValueError:      # 2024-02-31 and friends
        return None
    if not _FLOOR <= ts <= _CEILING:
        return None
    return ts, precision


#: How far apart two events of known precision must be before their order is
#: real rather than rounding.
_SLACK = {"day": DAY, "month": 31 * DAY, "year": 366 * DAY, "record": 0.0}


@dataclass
class Event:
    """One dated moment, with everything needed to argue about it."""

    when: float
    kind: EventKind
    label: str
    #: Who or what the date is about: the person prefix on the finding's label
    #: when there was one, else the module's own subject. Ordering is only
    #: testable *within* a subject - two different people's accounts may be
    #: created in any order at all.
    subject: str
    source: str
    precision: str = "day"
    value: str = ""
    url: str | None = None

    @property
    def iso(self) -> str:
        """The date at the precision we actually have, never more."""
        dt = datetime.fromtimestamp(self.when, tz=timezone.utc)
        if self.precision == "year":
            return dt.strftime("%Y")
        if self.precision == "month":
            return dt.strftime("%Y-%m")
        return dt.strftime("%Y-%m-%d")

    @property
    def slack(self) -> float:
        return _SLACK.get(self.precision, DAY)

    def to_dict(self) -> dict[str, Any]:
        return {"when": self.when, "iso": self.iso, "kind": self.kind.value,
                "label": self.label, "subject": self.subject,
                "source": self.source, "precision": self.precision,
                "value": self.value, "url": self.url}


@dataclass
class Timeline:
    """The chronology, plus what it implies that a list of dates does not."""

    events: list[Event] = field(default_factory=list)
    #: Reference clock: ``Investigation.started_at``. Every "days ago" below is
    #: measured from here, so the same case always reads the same way.
    as_of: float = 0.0
    #: Subjects whose most recent activity is long before the scan.
    dormant: list[tuple[str, float]] = field(default_factory=list)
    #: ``(a, b, days apart)`` - accounts created close enough together to be
    #: worth a look. Explicitly *not* a claim that they are related.
    clustered: list[tuple[str, str, float]] = field(default_factory=list)

    @property
    def span(self) -> tuple[float, float] | None:
        if not self.events:
            return None
        return self.events[0].when, self.events[-1].when

    @property
    def span_iso(self) -> tuple[str, str] | None:
        if not self.events:
            return None
        return self.events[0].iso, self.events[-1].iso

    def by_subject(self) -> dict[str, list[Event]]:
        out: dict[str, list[Event]] = {}
        for e in self.events:
            out.setdefault(e.subject, []).append(e)
        return out

    def rows(self, limit: int = 60) -> list[tuple[str, str, str]]:
        """``(iso, what, source)`` for a plain table renderer.

        The value is dropped when it only repeats the label. A graph
        observation with no detail has the evidence kind for both, and
        "passive-dns: passive-dns" is a line that costs a reader a second and
        tells them nothing.
        """
        out = []
        for e in self.events[:limit]:
            what = e.label
            if e.value and e.value.casefold() != e.label.casefold():
                what = f"{e.label}: {e.value}"
            out.append((e.iso, what, e.source))
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "as_of": self.as_of,
            "span": list(self.span_iso) if self.span_iso else None,
            "events": [e.to_dict() for e in self.events],
            "dormant": [{"subject": s, "days": round(d, 1)} for s, d in self.dormant],
            "clustered": [{"a": a, "b": b, "days_apart": round(d, 1)}
                          for a, b, d in self.clustered],
        }


# ---------------------------------------------------------------------------
# building it
# ---------------------------------------------------------------------------

#: Below this an account counts as abandoned rather than quiet. A year is the
#: conventional bar and is deliberately generous: plenty of real people post
#: twice a year, and calling them dormant on a six-month threshold would put a
#: misleading word next to a live account.
DORMANT_DAYS = 365.0

#: Accounts created within this of each other are worth *looking at* together.
#: Not evidence: registering two accounts in one sitting is exactly as common
#: as two strangers signing up the same week.
CLUSTER_DAYS = 2.0


def build(inv: Investigation) -> Timeline:
    """The chronology of one investigation.

    Reads three sources and de-duplicates across them: dated findings, graph
    observations that carry an ``observed_at``, and nothing else. Acquisition
    times are deliberately excluded - those are the clock of our own scanning.
    """
    events = _from_findings(inv) + _from_graph(inv)
    events = _dedupe(events)
    events.sort(key=lambda e: (e.when, e.subject, e.label))
    line = Timeline(events=events, as_of=inv.started_at)
    line.dormant = _dormant(events, inv.started_at)
    line.clustered = _clustered(events)
    return line


def _from_findings(inv: Investigation) -> list[Event]:
    out: list[Event] = []
    for result in inv.results:
        for finding in result.findings:
            label = str(finding.label)
            who, _, rest = label.partition(": ")
            if not rest:
                who, rest = result.target, label
            text = str(finding.value)
            parsed = None
            # An explicit observed_at beats anything scraped out of the text:
            # the module that set it knew what the date meant.
            if (finding.observed_at is not None
                    and _FLOOR <= finding.observed_at <= _CEILING):
                parsed = (finding.observed_at, "day")
            if parsed is None:
                if not _DATEY.search(rest):
                    continue
                parsed = parse_date(text)
            if parsed is None:
                continue
            when, precision = parsed
            out.append(Event(
                when=when, kind=_classify(rest), label=rest.strip(),
                subject=who.strip() or result.target, source=result.module,
                precision=precision, value=text[:120], url=finding.url))
    return out


def _from_graph(inv: Investigation) -> list[Event]:
    """Observations whose source dated the thing it asserted.

    ``recorded_at`` is ignored on purpose. It is the moment we read the page,
    and a chronology built from it is a chronology of the scan.
    """
    graph = inv.graph
    if graph is None:
        return []
    out: list[Event] = []
    for edge in graph.edges.values():
        for ob in edge.observations:
            if ob.observed_at is None:
                continue
            if not _FLOOR <= ob.observed_at <= _CEILING:
                continue
            node = graph.nodes.get(edge.dst)
            subject = node.entity.display if node else edge.dst
            out.append(Event(
                when=ob.observed_at, kind=_classify(ob.kind + " " + ob.detail),
                label=ob.detail or ob.kind, subject=subject,
                source=ob.module or "graph", precision="day",
                value=ob.kind, url=ob.url))
    return out


def _classify(text: str) -> EventKind:
    for kind, pattern in _KINDS:
        if pattern.search(text):
            return kind
    return EventKind.DATED


def _dedupe(events: list[Event]) -> list[Event]:
    """Two modules reporting one creation date is one event.

    Keyed on the day rather than the second, because the same fact arriving as
    a date from one source and a full timestamp from another is still one fact,
    and a timeline that lists it twice reads as two separate happenings.
    """
    seen: dict[tuple[str, str, int, str], Event] = {}
    for e in events:
        key = (e.subject.casefold(), e.kind.value, int(e.when // DAY),
               e.label.casefold())
        existing = seen.get(key)
        # Keep the more precise of the two, and the earlier source name for
        # stability so the same case renders identically every time.
        if existing is None or _SLACK.get(e.precision, DAY) < existing.slack:
            seen[key] = e
    return list(seen.values())


def _dormant(events: list[Event], as_of: float) -> list[tuple[str, float]]:
    """Subjects whose last sign of life is a long way before the scan."""
    latest: dict[str, float] = {}
    for e in events:
        if e.kind in (EventKind.LAST_ACTIVITY, EventKind.UPDATED,
                      EventKind.FIRST_ACTIVITY, EventKind.CREATED):
            latest[e.subject] = max(latest.get(e.subject, 0.0), e.when)
    out = [(subject, (as_of - when) / DAY)
           for subject, when in latest.items()
           if as_of > when and (as_of - when) / DAY >= DORMANT_DAYS]
    out.sort(key=lambda row: -row[1])
    return out


def _clustered(events: list[Event]) -> list[tuple[str, str, float]]:
    """Accounts created close together, as a question rather than an answer."""
    created = sorted((e for e in events if e.kind is EventKind.CREATED
                      and e.precision == "day"), key=lambda e: e.when)
    out: list[tuple[str, str, float]] = []
    for i, first in enumerate(created):
        for second in created[i + 1:]:
            gap = (second.when - first.when) / DAY
            if gap > CLUSTER_DAYS:
                break
            if first.subject.casefold() == second.subject.casefold():
                continue
            out.append((first.subject, second.subject, gap))
    return out


# ---------------------------------------------------------------------------
# conflicts
# ---------------------------------------------------------------------------


def chronology_conflicts(inv: Investigation) -> list[Contradiction]:
    """Orderings that cannot be right, as contradiction records.

    Only two tests, both of them arithmetic:

    *An effect before its cause.* An account cannot have been active before it
    existed. Real, and it happens: a renamed account inherits the old one's
    commits, and a republished archive carries a fresh timestamp over old
    material - both of which are in the explanation list rather than treated as
    proof of deception.

    *Two creation dates.* One subject, one creation event, two different
    sources giving two different answers more than a slack window apart.

    Anything at ``record`` precision or classified ``DATED`` is excluded: a
    date whose meaning we could not work out cannot contradict one whose
    meaning we could.
    """
    from .contradictions import Claim, Contradiction, ContradictionType, Resolution, Severity

    line = build(inv)
    out: list[Contradiction] = []
    for subject, events in line.by_subject().items():
        creations = [e for e in events if e.kind is EventKind.CREATED]
        activity = [e for e in events if e.kind in (EventKind.FIRST_ACTIVITY,
                                                    EventKind.LAST_ACTIVITY)]
        # effect before cause
        for created in creations:
            for act in activity:
                slack = max(created.slack, act.slack)
                if act.when >= created.when - slack:
                    continue
                out.append(Contradiction(
                    type=ContradictionType.CHRONOLOGY,
                    subject=subject,
                    severity=Severity.HIGH,
                    claims=[
                        Claim(value=f"{created.label} {created.iso}",
                              source=created.source, url=created.url,
                              observed_at=created.when),
                        Claim(value=f"{act.label} {act.iso}",
                              source=act.source, url=act.url,
                              observed_at=act.when),
                    ],
                    entities=[subject],
                    detail=(f"{subject} shows activity on {act.iso} but is "
                            f"recorded as created on {created.iso} - "
                            f"{(created.when - act.when) / DAY:.0f} days later"),
                ))
        # two creation dates
        for i, first in enumerate(creations):
            for second in creations[i + 1:]:
                slack = max(first.slack, second.slack)
                if abs(first.when - second.when) <= slack:
                    continue
                if first.source == second.source:
                    # One source giving two dates is a parsing problem on our
                    # side or a record with two fields, not a disagreement
                    # between sources. Saying otherwise cries wolf.
                    continue
                out.append(Contradiction(
                    type=ContradictionType.CHRONOLOGY,
                    subject=subject,
                    severity=Severity.MEDIUM,
                    claims=[
                        Claim(value=f"{first.label} {first.iso}",
                              source=first.source, url=first.url,
                              observed_at=first.when),
                        Claim(value=f"{second.label} {second.iso}",
                              source=second.source, url=second.url,
                              observed_at=second.when),
                    ],
                    entities=[subject],
                    resolution_status=Resolution.UNRESOLVED,
                    detail=(f"{subject} is dated to both {first.iso} "
                            f"({first.source}) and {second.iso} ({second.source})"),
                ))
    return out
