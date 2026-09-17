"""The dossier: an investigation reorganised around the subject.

Every renderer before this one groups output by **module**, which mirrors how
the work was done rather than what was learned. That is the right shape for
debugging a scan and the wrong shape for reading one. Nobody asks "what did the
whois module say"; they ask who this is, how to reach them, who they work with,
what infrastructure they run, and what is exposed.

So this reads the graph and the findings and answers those questions instead.

Three things it refuses to do
-----------------------------

**It does not decide who the subject is.** When a name matched four people, the
profile shows four candidates ranked by corroboration and says so. Picking one
is the analyst's judgement, and a dossier that silently picks for them is worse
than no dossier - it launders a guess into a heading.

**It does not promote a finding by putting it in a section.** Everything keeps
the grade the evidence earned. A relationship at ``D3`` appears under
Relationships looking exactly as weak as it is.

**It does not quietly drop what it could not find.** Empty sections are printed
as empty, and the coverage gaps travel with the profile, because in a dossier
the absence of a section reads as "nothing there" rather than "never looked".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .entities import EntityType
from .graph import EntityGraph, probability
from .models import Investigation, Severity

# ---------------------------------------------------------------------------
# sections
# ---------------------------------------------------------------------------

#: ``(heading, entity kinds, one line on how to read it)``. Ordered the way an
#: analyst reads a dossier: who, how to reach them, who with, what they run.
_ALL_SECTIONS: dict[str, tuple[tuple[EntityType, ...], str]] = {
    "Identity": ((EntityType.PERSON,),
                 "names this subject is known by, and candidates sharing the name"),
    "Accounts": ((EntityType.USERNAME,),
                 "handles, ranked by how well corroborated they are"),
    "Contact": ((EntityType.EMAIL, EntityType.PHONE, EntityType.ADDRESS),
                "addresses and numbers found in public records"),
    "Affiliations": ((EntityType.ORG,),
                     "employers, memberships and corporate relationships"),
    "Infrastructure": ((EntityType.DOMAIN, EntityType.HOST, EntityType.IP,
                        EntityType.CIDR, EntityType.ASN),
                       "domains, hosts and networks connected to the subject"),
    "Fingerprints": ((EntityType.KEY, EntityType.SPKI, EntityType.CERT,
                      EntityType.TRACKER, EntityType.FAVICON, EntityType.FILEHASH),
                     "shared identifiers that link this subject to other things"),
}

#: Section order per kind of subject, most important first.
#:
#: A person and a domain want opposite orderings and one list cannot serve both.
#: For a person, infrastructure is trivia and who they are is the answer; for a
#: domain it is the reverse, and leading a domain report with "Identity: none
#: found" is noise dressed up as rigour.
_ORDER = {
    "person": ("Identity", "Accounts", "Contact", "Affiliations",
               "Fingerprints", "Infrastructure"),
    "infrastructure": ("Infrastructure", "Contact", "Affiliations", "Accounts",
                       "Fingerprints", "Identity"),
}

#: Default view, kept as a module constant because the renderers and the tests
#: both import it. :func:`sections_for` is what a renderer should actually call.
SECTIONS: list[tuple[str, tuple[EntityType, ...], str]] = [
    (name, *_ALL_SECTIONS[name]) for name in _ORDER["person"]
]


def sections_for(subject_type: str) -> list[tuple[str, tuple[EntityType, ...], str]]:
    """The section order that suits this kind of subject."""
    key = "person" if subject_type in ("person", "username", "email") \
        else "infrastructure"
    return [(name, *_ALL_SECTIONS[name]) for name in _ORDER[key]]

#: Entity kinds that are people rather than things. Relationships between two of
#: these are the part of a profile that is hardest to get elsewhere.
PEOPLE = (EntityType.PERSON, EntityType.USERNAME, EntityType.EMAIL)

#: Labels whose value is a date worth putting on a timeline. Matching on the
#: label rather than sniffing every value keeps a random hash that happens to
#: contain eight digits out of the chronology.
_DATEY = re.compile(r"creat|regist|found|incept|first|last|expir|updat|push|born|"
                    r"issued|seen|inception", re.I)
_ISO_DATE = re.compile(r"(\d{4}-\d{2}-\d{2})")
_YEAR = re.compile(r"\b(19\d{2}|20\d{2})\b")


@dataclass
class Entry:
    """One line in a profile section.

    Carries **two** numbers, because they answer different questions and the
    first version of this conflated them.

    ``score`` is relevance: how strongly this is tied back to the thing you
    searched for. ``llr`` is corroboration: how well evidenced the entity is in
    its own right. A handle Wikidata declares for a *candidate* who may or may
    not be your subject is well evidenced and only loosely connected - high
    llr, low score - and a reader needs both numbers to tell which it is.
    """

    value: str
    etype: str
    grade: str
    score: float
    why: str
    llr: float = 0.0
    sources: list[str] = field(default_factory=list)
    path: list[str] = field(default_factory=list)

    @property
    def corroboration(self) -> int:
        """How many independent modules saw this."""
        return len(self.sources)

    def to_dict(self) -> dict[str, Any]:
        return {"value": self.value, "type": self.etype, "grade": self.grade,
                "score": round(self.score, 4), "llr": round(self.llr, 3),
                "corroboration": self.corroboration, "why": self.why,
                "sources": self.sources, "path": self.path}


@dataclass
class Relationship:
    """A link between two entities, at least one of which is not the subject."""

    a: str
    b: str
    relation: str
    grade: str
    llr: float
    why: str
    reading: str
    #: True when neither end is the seed - a connection *between* other people,
    #: which is the thing a flat scan can never show.
    indirect: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"from": self.a, "to": self.b, "relation": self.relation,
                "grade": self.grade, "llr": round(self.llr, 3), "why": self.why,
                "reading": self.reading, "indirect": self.indirect}


@dataclass
class Profile:
    subject: str
    subject_type: str
    sections: dict[str, list[Entry]] = field(default_factory=dict)
    relationships: list[Relationship] = field(default_factory=list)
    timeline: list[tuple[str, str, str]] = field(default_factory=list)
    exposure: list[tuple[str, str, str]] = field(default_factory=list)
    ambiguities: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    #: Biographical attributes, most important first. Empty for anything that
    #: is not a person.
    bio: list[Any] = field(default_factory=list)
    #: The section order this subject was rendered with.
    order: list[str] = field(default_factory=list)
    #: One row per social platform, with the profile link. Populated from every
    #: URL the investigation produced, whichever module found it.
    socials: list[Any] = field(default_factory=list)
    #: ``(entity, score, why)`` when the subject itself is uncertain.
    candidates: list[Entry] = field(default_factory=list)
    entities: int = 0
    findings: int = 0
    duration: float = 0.0
    truncated: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject, "subject_type": self.subject_type,
            "summary": {"entities": self.entities, "findings": self.findings,
                        "relationships": len(self.relationships),
                        "duration": round(self.duration, 2),
                        "truncated": self.truncated},
            "biography": [a.to_dict() for a in self.bio],
            "candidates": [c.to_dict() for c in self.candidates],
            "sections": {k: [e.to_dict() for e in v] for k, v in self.sections.items()},
            "relationships": [r.to_dict() for r in self.relationships],
            "timeline": [{"when": w, "what": what, "source": s}
                         for w, what, s in self.timeline],
            "exposure": [{"label": a, "value": b, "module": c}
                         for a, b, c in self.exposure],
            "social_accounts": [a.to_dict() for a in self.socials],
            "ambiguities": self.ambiguities,
            "coverage_gaps": self.gaps,
        }


# ---------------------------------------------------------------------------
# building
# ---------------------------------------------------------------------------


def build(inv: Investigation, *, per_section: int = 25,
          min_score: float = 0.0) -> Profile:
    """Reorganise an investigation into a dossier."""
    from .graphview import probability_note
    from .report import status_rows

    graph: EntityGraph | None = inv.graph
    profile = Profile(subject=inv.target, subject_type=inv.target_type.value,
                      findings=len(inv.findings), duration=inv.duration)
    if inv.expansion is not None and inv.expansion.stopped_by != "frontier exhausted":
        profile.truncated = inv.expansion.stopped_by
    profile.gaps = [f"{m}: {s}" + (f" - {r}" if r else "")
                    for m, s, r in status_rows(inv)]

    # Before the graph early-return, deliberately. The biography is read from
    # findings, not from entities, so a scan that linked nothing must still be
    # able to say who the subject is - and a person scan that produced no graph
    # was silently losing the entire block.
    from .biography import extract as extract_bio

    profile.bio = extract_bio(inv)
    layout = sections_for(profile.subject_type)
    profile.order = [name for name, _k, _n in layout]

    from .socials import collect as collect_socials

    handles = set()
    if graph is not None:
        handles = {n.entity.value for n in graph
                   if n.entity.etype is EntityType.USERNAME}
    profile.socials = collect_socials(inv, handles)

    # Ambiguity is load-bearing, so it is lifted out of the findings where it
    # would otherwise sit in the middle of a module's output and be missed.
    for result in inv.results:
        for finding in result.findings:
            if finding.label == "ambiguity":
                profile.ambiguities.append(f"{result.module}: {finding.value}")

    if graph is None or not len(graph):
        return profile

    profile.entities = len(graph)
    seed = graph.seed

    for heading, kinds, _note in layout:
        entries = []
        for node in graph:
            if node.entity.etype not in kinds or node.entity.eid == seed:
                continue
            if node.score < min_score:
                continue
            edges = graph.edges_of(node.entity.eid)
            best = max(edges, key=lambda e: e.llr, default=None)
            entries.append(Entry(
                value=node.entity.display,
                etype=node.entity.etype.value,
                grade=best.grade if best else "E5",
                score=node.score,
                llr=best.llr if best else 0.0,
                why=", ".join(sorted({o.kind for e in edges for o in e.observations})),
                sources=sorted(node.sources),
                path=graph.path(node.entity.eid),
            ))
        # Evidence first, relevance second. Ranking purely by relevance puts a
        # guess that happens to sit one hop from the seed above a handle two
        # independent sources agree on, which is the wrong way round for anyone
        # reading a candidate list.
        entries.sort(key=lambda e: (-e.llr, -e.corroboration, -e.score, e.value))
        profile.sections[heading] = entries[:per_section]

    profile.relationships = _relationships(graph, probability_note)
    profile.candidates = _candidates(graph, profile)
    profile.timeline = _timeline(inv)
    profile.exposure = _exposure(inv)
    return profile


def _relationships(graph: EntityGraph, reading: Any) -> list[Relationship]:
    """Edges worth showing as relationships, strongest first.

    An edge between two entities that are *both* other people is promoted above
    the rest, because that is the thing a flat scan can never produce and the
    reason a graph is worth keeping at all.
    """
    out = []
    for edge in graph.edges.values():
        src, dst = graph.nodes.get(edge.src), graph.nodes.get(edge.dst)
        if src is None or dst is None:
            continue
        if src.entity.etype not in PEOPLE and dst.entity.etype not in PEOPLE:
            continue
        if edge.llr <= 0:
            continue
        indirect = graph.seed not in (edge.src, edge.dst)
        out.append(Relationship(
            a=src.entity.display, b=dst.entity.display, relation=edge.label,
            grade=edge.grade, llr=edge.llr,
            why=", ".join(sorted({o.kind for o in edge.observations})),
            reading=reading(edge.llr), indirect=indirect,
        ))
    out.sort(key=lambda r: (not r.indirect, -r.llr, r.a))
    return out


def _candidates(graph: EntityGraph, profile: Profile) -> list[Entry]:
    """Who the subject might be, when the subject is a name.

    Only populated when the seed is a PERSON: that is the case where the tool
    genuinely does not know who it is looking at, and saying so at the top of
    the document is the difference between a dossier and a guess.
    """
    seed = graph.nodes.get(graph.seed or "")
    if seed is None or seed.entity.etype is not EntityType.PERSON:
        return []
    out = []
    for node in graph:
        if node.entity.etype is not EntityType.PERSON or node.entity.eid == graph.seed:
            continue
        edges = graph.edges_of(node.entity.eid)
        best = max(edges, key=lambda e: e.llr, default=None)
        out.append(Entry(
            value=node.entity.display, etype="person",
            grade=best.grade if best else "E5", score=node.score,
            llr=best.llr if best else 0.0,
            why=", ".join(sorted({o.kind for e in edges for o in e.observations})),
            sources=sorted(node.sources),
        ))
    out.sort(key=lambda e: (-e.llr, -e.corroboration, -e.score))
    return out


def _timeline(inv: Investigation) -> list[tuple[str, str, str]]:
    """Dated facts in order. A chronology is often the whole answer."""
    rows: list[tuple[str, str, str]] = []
    for result in inv.results:
        for finding in result.findings:
            if not _DATEY.search(finding.label):
                continue
            text = str(finding.value)
            match = _ISO_DATE.search(text) or _YEAR.search(text)
            if not match:
                continue
            rows.append((match.group(1), f"{finding.label}: {text[:90]}",
                         result.module))
    # De-duplicated because two modules often report the same creation date, and
    # a chronology that says a thing happened twice is worse than useless.
    seen: set[tuple[str, str]] = set()
    unique = []
    for when, what, module in sorted(rows):
        key = (when, what)
        if key in seen:
            continue
        seen.add(key)
        unique.append((when, what, module))
    return unique


def _exposure(inv: Investigation) -> list[tuple[str, str, str]]:
    """The findings that are somebody's problem rather than just facts."""
    out = []
    for result in inv.results:
        for finding in result.findings:
            if finding.severity is Severity.HIGH:
                out.append((finding.label, str(finding.value)[:120], result.module))
    return out


def confidence_line(profile: Profile) -> str:
    """One sentence on how much of this dossier is actually supported."""
    graded = [e for entries in profile.sections.values() for e in entries]
    if not graded:
        return "nothing was linked to this subject."
    strong = sum(1 for e in graded if e.grade[0] in "AB")
    weak = sum(1 for e in graded if e.grade[0] in "DE")
    return (f"{len(graded)} linked entities: {strong} on strong evidence, "
            f"{weak} on weak or none. "
            + ("Treat the weak ones as leads, not facts."
               if weak else "Every link is well evidenced."))


def probability_of(llr: float) -> float:
    return probability(llr)
