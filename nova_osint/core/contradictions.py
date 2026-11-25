"""Everything in one investigation that disagrees with something else in it.

NOVA already detected disagreement in three places, and that was the problem.
``graph._contradict()`` knows an edge argues against a node. ``identity``
knows a candidate states something incompatible with the brief.
``biography.Attribute.disputed`` knows two sources gave two answers. Three
mechanisms, three vocabularies, three output shapes, and no single place a
reader could ask *what contradicts what* - so in practice nobody asked.

This module does not detect anything new about log-odds. It reads the four
existing detectors plus the chronology from :mod:`~nova_osint.core.temporal`,
and turns all of them into one record with one shape.

Two rules it will not bend
--------------------------

**A contradiction is not proof that one side is false.** It is the observation
that two claims cannot both be true *as stated*, which has at least six
ordinary explanations before anybody has lied: two different people with one
name, a stale record, a reused account, a profile the owner never updated, a
pseudonym, a source that simply got it wrong. Every contradiction therefore
carries :attr:`Contradiction.possible_explanations`, and the engine never picks
one. Picking one is the analyst's job, and an analyst who is handed a verdict
instead of a disagreement has been robbed of the interesting part.

**Severity is about how identifying the claim is, not how loud the clash is.**
Two sources disagreeing about a bio blurb is noise. Two sources disagreeing
about a date of birth is the whole case. The weights come from
:data:`SEVERITY_BY_KIND` rather than from the size of the log-odds gap, because
a large gap between two weak sources is still two weak sources.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .models import Investigation

# ---------------------------------------------------------------------------
# vocabulary
# ---------------------------------------------------------------------------


class ContradictionType(str, Enum):
    """What kind of thing disagrees.

    Kept coarse on purpose. A reader scanning a report needs to know whether
    two *sources* disagree about a fact or whether the *evidence* argues a lead
    does not belong at all; finer distinctions than that belong in the detail
    line, not in a type they have to learn.
    """

    #: Two sources gave different answers for one biographical attribute.
    ATTRIBUTE = "attribute"
    #: Evidence against a graph node outweighs the evidence for it.
    RULED_OUT = "ruled out"
    #: A candidate identity states something incompatible with the brief.
    CLAIM = "claim"
    #: The chronology does not work: an effect dated before its cause.
    CHRONOLOGY = "chronology"
    #: One identifier claimed by two entities that cannot both own it.
    OWNERSHIP = "ownership"


class Severity(str, Enum):
    """How much this disagreement should change what the reader believes."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Resolution(str, Enum):
    """What has been done about it. NOVA only ever sets the first two."""

    #: Nobody has adjudicated it. The default and the honest one.
    UNRESOLVED = "unresolved"
    #: The evidence itself settles it - one side is decisively better sourced.
    EVIDENCE_FAVOURS_ONE = "evidence favours one side"
    #: An analyst resolved it. Only ever set from outside this module.
    ANALYST_RESOLVED = "analyst resolved"


#: How much a disagreement about this attribute matters, by the label
#: :mod:`~nova_osint.core.biography` gives it.
#:
#: These mirror the asymmetry already encoded in ``identity.POWER``: people
#: move city and change jobs constantly, so those disagreements are weak
#: evidence of anything; nobody has two dates of birth, so that one is
#: decisive. Anything unlisted is MEDIUM - unknown is not the same as harmless.
SEVERITY_BY_KIND: dict[str, Severity] = {
    "Date of birth": Severity.HIGH,
    "Date of death": Severity.HIGH,
    "Place of birth": Severity.HIGH,
    "Name": Severity.HIGH,
    "Nationality": Severity.MEDIUM,
    "Gender": Severity.MEDIUM,
    "Education": Severity.MEDIUM,
    "Employer": Severity.LOW,
    "Occupation": Severity.LOW,
    "Position held": Severity.LOW,
    "Based in": Severity.LOW,
    "Likely timezone": Severity.LOW,
    "Languages": Severity.LOW,
    "Organisations": Severity.LOW,
    "Bio": Severity.LOW,
    "Also known as": Severity.LOW,
}

#: The standing catalogue of innocent explanations, per contradiction type.
#:
#: Written out rather than generated because the whole point is that the reader
#: sees the *same* list every time and stops reading a clash as an accusation.
#: A tool that only volunteers "these may be two different people" when it
#: happens to be unsure has taught its reader that silence means guilt.
EXPLANATIONS: dict[ContradictionType, tuple[str, ...]] = {
    ContradictionType.ATTRIBUTE: (
        "two different people sharing a name or handle",
        "one source is stale and was never corrected",
        "the subject changed the detail (moved, remarried, changed jobs)",
        "a profile the owner filled in inaccurately or as a joke",
        "one source transcribed or parsed it wrongly",
        "the attribute genuinely has several values at once",
    ),
    ContradictionType.RULED_OUT: (
        "the account belongs to a different person with the same handle",
        "the denial is a soft-404 or a rate limit misread as a denial",
        "the account was renamed or deleted between the two observations",
        "the positive evidence was a coincidental match",
    ),
    ContradictionType.CLAIM: (
        "this candidate is not the subject",
        "the brief itself is wrong or out of date",
        "the source describes a different period of the subject's life",
        "the candidate's profile is inaccurate",
    ),
    ContradictionType.CHRONOLOGY: (
        "one of the two dates is the date of a record, not of the event",
        "an account was renamed and inherited an older or newer history",
        "a source republished old material with a new timestamp",
        "a timezone or date-format misreading of one of the two values",
        "the two records are about different subjects",
    ),
    ContradictionType.OWNERSHIP: (
        "a shared mailbox, team account or role address",
        "the identifier was transferred between owners",
        "one of the two claims is an aggregator repeating the other",
        "the identifier was reused after being released",
    ),
}


# ---------------------------------------------------------------------------
# the record
# ---------------------------------------------------------------------------


@dataclass
class Claim:
    """One side of a disagreement, with who said it."""

    value: str
    source: str
    url: str | None = None
    #: Admiralty grade or other strength label, when the layer that found it
    #: had one. Blank rather than invented when it did not.
    grade: str = ""
    #: Unix timestamp of when the *source* says this was true, when known.
    observed_at: float | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"value": self.value, "source": self.source}
        if self.url:
            d["url"] = self.url
        if self.grade:
            d["grade"] = self.grade
        if self.observed_at is not None:
            d["observed_at"] = self.observed_at
        return d


@dataclass
class Contradiction:
    """Two claims that cannot both be true as stated, and why that may be fine."""

    type: ContradictionType
    #: What the disagreement is about: an attribute label, an entity id, a
    #: candidate name. Not a sentence - the sentence is :attr:`summary`.
    subject: str
    claims: list[Claim] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    #: Entity ids or target values involved, for the graph view to highlight.
    entities: list[str] = field(default_factory=list)
    resolution_status: Resolution = Resolution.UNRESOLVED
    #: Overrides :data:`EXPLANATIONS` when the detector knows something more
    #: specific. Appended to the standing list rather than replacing it.
    extra_explanations: tuple[str, ...] = ()
    detail: str = ""

    @property
    def possible_explanations(self) -> list[str]:
        """Ordinary reasons both claims could stand without anybody lying."""
        return list(EXPLANATIONS.get(self.type, ())) + list(self.extra_explanations)

    @property
    def summary(self) -> str:
        """One line, for a report that has room for one line."""
        if self.detail:
            return self.detail
        sources = " vs ".join(dict.fromkeys(c.source for c in self.claims))
        return f"{self.subject}: {len(self.claims)} conflicting values ({sources})"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "subject": self.subject,
            "summary": self.summary,
            "severity": self.severity.value,
            "entities": self.entities,
            "claims": [c.to_dict() for c in self.claims],
            "possible_explanations": self.possible_explanations,
            "resolution_status": self.resolution_status.value,
        }


#: Sort order for a report: worst first, then by how many sources are involved.
_RANK = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}


# ---------------------------------------------------------------------------
# detection
# ---------------------------------------------------------------------------


def detect(inv: Investigation) -> list[Contradiction]:
    """Every disagreement in one investigation, worst first.

    Safe on a bare ``Investigation``: each detector returns nothing when the
    layer it reads was never populated, so a plain ``nova scan`` with no graph,
    no brief and no biography yields ``[]`` rather than raising.
    """
    found: list[Contradiction] = []
    found += _from_biography(inv)
    found += _from_graph(inv)
    found += _from_resolution(inv)
    found += _from_chronology(inv)
    found.sort(key=lambda c: (_RANK[c.severity], -len(c.claims), c.subject))
    return found


def _from_biography(inv: Investigation) -> list[Contradiction]:
    """Two sources, two answers, one attribute.

    Reuses ``biography.Attribute.disputed``, which already refuses to call
    three degrees from one encyclopaedia a disagreement. The bar is *different
    sources*, not merely different values.
    """
    from . import biography

    out: list[Contradiction] = []
    try:
        subjects = biography.extract(inv)
    except Exception:       # a malformed finding must not cost the whole report
        return out
    for subject in subjects:
        for attr in subject.attributes:
            if not attr.disputed:
                continue
            who = f"{subject.name}: {attr.label}" if subject.name else attr.label
            out.append(Contradiction(
                type=ContradictionType.ATTRIBUTE,
                subject=who,
                severity=SEVERITY_BY_KIND.get(attr.label, Severity.MEDIUM),
                claims=[Claim(value=v.text, source=v.basis, url=v.url, grade=v.grade)
                        for v in attr.values],
                entities=[subject.name] if subject.name else [],
                extra_explanations=(
                    ("this source resolves the name to several people",)
                    if subject.candidate else ()),
                detail=(f"{attr.label} is given as "
                        + " / ".join(dict.fromkeys(v.text for v in attr.values))),
            ))
    return out


def _from_graph(inv: Investigation) -> list[Contradiction]:
    """Nodes the evidence argues against more strongly than for.

    ``Node.contradicted`` is already computed by ``EntityGraph._contradict``;
    this only reads it. The severity is the one place a log-odds number is
    consulted, because here the two sides *are* log-odds and their gap is the
    honest measure of how much the denial matters.
    """
    graph = inv.graph
    if graph is None:
        return []
    out: list[Contradiction] = []
    for node in graph.contradicted():
        gap = abs(node.support + node.against)
        severity = (Severity.HIGH if gap >= 3.0
                    else Severity.MEDIUM if gap >= 1.0 else Severity.LOW)
        claims = [
            Claim(value=f"belongs to the investigation (+{node.support:.2f} nats)",
                  source=", ".join(sorted(node.sources)) or "graph"),
            Claim(value=f"does not belong ({node.against:.2f} nats)",
                  source=", ".join(sorted(node.sources)) or "graph"),
        ]
        for edge in graph.edges_of(node.entity.eid):
            for ob in edge.observations:
                if ob.strength < 0:
                    claims.append(Claim(
                        value=ob.detail or f"{ob.kind} argues against",
                        source=ob.module or "unknown", url=ob.url,
                        observed_at=ob.observed_at))
        out.append(Contradiction(
            type=ContradictionType.RULED_OUT,
            subject=node.entity.display,
            severity=severity,
            claims=claims,
            entities=[node.entity.eid],
            # The gap is the arithmetic; it decides nothing on its own, but a
            # decisive one is worth saying out loud rather than leaving the
            # reader to subtract two numbers in a table.
            resolution_status=(Resolution.EVIDENCE_FAVOURS_ONE if gap >= 3.0
                               else Resolution.UNRESOLVED),
            detail=(f"{node.entity.display} was found and ruled out: "
                    f"{node.against:.2f} nats against, "
                    f"{node.support:.2f} for"),
        ))
    return out


def _from_resolution(inv: Investigation) -> list[Contradiction]:
    """Candidates whose own data contradicts the brief.

    Only decisive checks become contradictions. ``identity`` deliberately
    scores a mismatched employer at -0.3, which is a nudge, not a disagreement,
    and promoting every nudge here would bury the four that matter.
    """
    resolution = inv.resolution
    if resolution is None:
        return []
    from .identity import Verdict

    out: list[Contradiction] = []
    for candidate in getattr(resolution, "candidates", []):
        for check in candidate.checks:
            if check.verdict is not Verdict.CONTRADICTS:
                continue
            if not check.decisive:
                continue
            out.append(Contradiction(
                type=ContradictionType.CLAIM,
                subject=f"{candidate.label}: {check.claim.kind.value}",
                severity=Severity.HIGH if abs(check.llr) >= 4.0 else Severity.MEDIUM,
                claims=[
                    Claim(value=str(check.claim.raw), source="the brief you gave"),
                    Claim(value=check.found or "something incompatible",
                          source=check.source or "scan"),
                ],
                entities=[candidate.label],
                detail=(f"{candidate.label} states {check.found!r} where the brief "
                        f"says {check.claim.raw!r} ({check.llr:+.2f} nats)"),
            ))
    return out


def _from_chronology(inv: Investigation) -> list[Contradiction]:
    """Dates that cannot both be right.

    Delegated to :mod:`~nova_osint.core.temporal` so there is one chronology
    and not two. Imported inside the function because ``temporal`` reads this
    module's vocabulary for its own return type.
    """
    from .temporal import chronology_conflicts

    return chronology_conflicts(inv)


# ---------------------------------------------------------------------------
# reporting helpers
# ---------------------------------------------------------------------------


def counts(found: list[Contradiction]) -> dict[str, int]:
    """``{severity: n}`` plus a total, for the evidence summary."""
    out = {s.value: 0 for s in Severity}
    for c in found:
        out[c.severity.value] += 1
    out["total"] = len(found)
    return out


def rows(found: list[Contradiction], limit: int = 25
         ) -> list[tuple[str, str, str, str]]:
    """``(severity, type, subject, summary)`` for a plain table renderer."""
    return [(c.severity.value, c.type.value, c.subject, c.summary)
            for c in found[:limit]]
