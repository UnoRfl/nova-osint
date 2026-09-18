"""Identity resolution: which of these candidates is actually your subject.

Every other part of NOVA answers *"what is connected to this?"*. This answers
the question people actually arrive with, which is *"I know six things about
someone - which of these forty search results is them?"*

It needs a :class:`~nova_osint.core.brief.Brief` to work, because with a single
seed the question is unanswerable in principle. A name search returns a set of
people and nothing in the results can rank them; that is not a weakness of the
search, it is what a name *is*. Give the same search a city and a birth year and
thirty-eight of the forty answer themselves.

How it works
------------

**1. Cluster.** Accounts, profiles and named entities are grouped into identities
by transitive closure over strong edges, so a Bluesky handle, its bare stem and
a GitHub account carrying the same key are one candidate rather than three. The
idea is borrowed from Metasploit's vulnerability grouping, which merges findings
that share references into families before deciding what to do about them - the
useful part being that the grouping is done by *shared identifiers*, not by
similarity of names.

**2. Check each claim against each candidate**, producing a graded
:class:`Verdict` with a reason rather than a boolean. Metasploit's ``CheckCode``
has the shape worth copying here: ``Unknown`` and ``Unsupported`` are separate
outcomes, because "I looked and could not tell" and "nothing here can tell you"
are different facts about the world and collapsing them loses the more important
one. NOVA has always insisted on that distinction for coverage; this brings it
to identity.

**3. Score in log-odds**, summing the brief's own weights. Confirming a phone
number is worth six nats; confirming a first name is worth two tenths of one.
Contradicting an employer is worth almost nothing because profiles go stale,
while contradicting a date of birth is decisive. Those asymmetries live in
:data:`~nova_osint.core.brief.POWER` and this module just adds them up.

**4. Say what would settle it.** When the top two candidates are close, the
useful output is not a ranking, it is the single unchecked fact that would
separate them - and it is computable: the claim with the most identifying power
that neither candidate has answered. Nothing else in the tool tells you what to
do next; a ranked list that leaves the reader to guess has done half the job.

What it will not do
-------------------

**It never declares a match.** The top candidate is reported with its score, its
evidence and the reasons against it. Deciding is the analyst's job, and a tool
that decides for them is one that will eventually be confidently wrong about a
real person. The output is built so that an unconvincing result *looks*
unconvincing, and so that a contradiction is as visible as a confirmation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .brief import Brief, Claim, ClaimKind
from .entities import EntityType
from .models import Investigation

# ---------------------------------------------------------------------------
# verdicts
# ---------------------------------------------------------------------------


class Verdict(str, Enum):
    """What a candidate's own data says about one claim in the brief.

    Five outcomes rather than match/no-match, because the three in the middle
    are where the honesty lives. ``UNKNOWN`` means nobody published this;
    ``UNCHECKED`` means the source that would have said so was not reachable
    this run. Only the second is a reason to go and look again, and a tool that
    reports both as "no" tells the reader to give up on the wrong one.
    """

    CONFIRMS = "confirms"        # the candidate's own data states this exact thing
    CONSISTENT = "consistent"    # compatible, not identical - "KL" vs "Kuala Lumpur"
    UNKNOWN = "unknown"          # nothing published either way
    UNCHECKED = "unchecked"      # no source that could answer was reachable
    CONTRADICTS = "contradicts"  # the candidate states something incompatible


#: How much of a claim's weight each verdict carries.
#:
#: ``CONSISTENT`` is deliberately well below ``CONFIRMS``: "London, UK" matching
#: a claim of "London" is real support, but it is also what a hundred thousand
#: profiles say, and treating a loose match as an exact one is how these tools
#: manufacture certainty.
_WEIGHT = {
    Verdict.CONFIRMS: 1.0,
    Verdict.CONSISTENT: 0.35,
    Verdict.UNKNOWN: 0.0,
    Verdict.UNCHECKED: 0.0,
    Verdict.CONTRADICTS: 1.0,   # applied to the (negative) contradict weight
}

#: Evidence kinds that mean **the same actor controls both ends**, which is a
#: different question from how strong the edge is.
#:
#: Strength is the wrong signal here and using it was a bug: ``educated-at``
#: and ``spouse`` are worth 3-4 nats precisely because they are well attested,
#: and merging on that folded a university and a husband into the person. What
#: matters is whether the evidence could only have been produced by one person
#: - a shared private key, a signed cross-proof, an address published on the
#: account's own profile.
#:
#: Infrastructure evidence (shared certificates, tracker ids, DNS) is left out
#: deliberately. It genuinely does link one *operator's* estate together, but
#: an identity here is a person or an organisation, and two domains behind one
#: CDN account are not one subject.
_IDENTITY_EVIDENCE = frozenset({
    "key-fingerprint-shared",   # the same private key signed both
    "key-uid",                  # an identity baked into a published key
    "keybase-proof",            # a signed statement linking two accounts
    "webfinger-proof",
    "gravatar-hash",            # an address hash resolving to a profile
    "commit-email",             # an author address in a pushed commit
    "profile-email",            # an address the account holder published
})

#: Relation labels that assert sameness directly, for modules that know two
#: nodes are one thing without cryptographic proof.
#:
#: ``handle-stem`` is deliberately **absent**. It reads as "this is the same
#: handle without its domain", and it is - but modules emit it from the
#: *subject* to a candidate's stem, so treating it as sameness merged every
#: search result into the thing being searched for. A relation means what the
#: code that emits it means, not what its name suggests.
_SAME_IDENTITY_RELATIONS = frozenset({"same-as", "alias-of"})


@dataclass
class Check:
    """One claim, tested against one candidate."""

    claim: Claim
    verdict: Verdict
    #: What the candidate's own data actually said, for the reader to judge.
    found: str = ""
    llr: float = 0.0
    why: str = ""
    source: str = ""

    @property
    def decisive(self) -> bool:
        return abs(self.llr) >= 3.0

    def to_dict(self) -> dict[str, Any]:
        return {"claim": self.claim.kind.value, "expected": self.claim.raw,
                "verdict": self.verdict.value, "found": self.found,
                "llr": round(self.llr, 3), "why": self.why, "source": self.source}


@dataclass
class Candidate:
    """One possible identity for the subject, and the case for and against it."""

    label: str
    etype: str
    #: Every entity value folded into this identity by clustering.
    members: list[str] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    url: str = ""
    #: Relevance from the graph, kept separate from the brief score because
    #: they answer different questions: one is "is this connected to what I
    #: searched", the other is "is this the person I described".
    relevance: float = 0.0

    @property
    def score(self) -> float:
        """Total log-odds from the brief. Positive argues for, negative against."""
        return sum(c.llr for c in self.checks)

    @property
    def probability(self) -> float:
        from .graph import probability

        return probability(self.score)

    @property
    def confirmed(self) -> list[Check]:
        return [c for c in self.checks if c.verdict is Verdict.CONFIRMS]

    @property
    def against(self) -> list[Check]:
        return [c for c in self.checks if c.verdict is Verdict.CONTRADICTS]

    @property
    def unchecked(self) -> list[Check]:
        return [c for c in self.checks if c.verdict is Verdict.UNCHECKED]

    @property
    def answered(self) -> int:
        """How many claims this candidate's data spoke to at all.

        Reported beside the score because a candidate scoring 6.5 on one
        matched address out of eight claims is a very different object from one
        scoring 6.5 across six, and a bare number hides that completely.
        """
        return len([c for c in self.checks
                    if c.verdict in (Verdict.CONFIRMS, Verdict.CONSISTENT,
                                     Verdict.CONTRADICTS)])

    def to_dict(self) -> dict[str, Any]:
        return {"label": self.label, "type": self.etype, "members": self.members,
                "score": round(self.score, 3),
                "probability": round(self.probability, 4),
                "answered": self.answered, "relevance": round(self.relevance, 4),
                "url": self.url, "sources": self.sources,
                "checks": [c.to_dict() for c in self.checks]}


@dataclass
class Resolution:
    """The answer, such as it is, plus what would improve it."""

    subject: str
    candidates: list[Candidate] = field(default_factory=list)
    #: One sentence on how much the evidence actually supports the leader.
    reading: str = ""
    #: The claim worth establishing next, and why it would help.
    next_check: str = ""
    #: Claims in the brief that nothing in this scan could ever have tested.
    untestable: list[str] = field(default_factory=list)

    @property
    def leader(self) -> Candidate | None:
        return self.candidates[0] if self.candidates else None

    @property
    def margin(self) -> float:
        """How far ahead the leader is, in nats. Small means do not trust it."""
        if len(self.candidates) < 2:
            return self.candidates[0].score if self.candidates else 0.0
        return self.candidates[0].score - self.candidates[1].score

    def to_dict(self) -> dict[str, Any]:
        return {"subject": self.subject, "reading": self.reading,
                "margin": round(self.margin, 3), "next_check": self.next_check,
                "untestable": self.untestable,
                "candidates": [c.to_dict() for c in self.candidates]}


# ---------------------------------------------------------------------------
# what a candidate's data says
# ---------------------------------------------------------------------------

#: Biography attribute labels mapped onto claim kinds. Reuses the extraction in
#: :mod:`nova_osint.core.biography` rather than re-deriving it, so a module that
#: learns to report an employer starts feeding identity resolution the same day
#: it starts feeding the dossier.
_BIO_TO_CLAIM: dict[str, ClaimKind] = {
    "Name": ClaimKind.NAME,
    "Also known as": ClaimKind.NAME,
    "Date of birth": ClaimKind.BORN,
    "Nationality": ClaimKind.COUNTRY,
    "Based in": ClaimKind.CITY,
    "Occupation": ClaimKind.ROLE,
    "Employer": ClaimKind.ORG,
    "Organisations": ClaimKind.ORG,
    "Education": ClaimKind.SCHOOL,
    "Languages": ClaimKind.LANGUAGE,
    "Bio": ClaimKind.KEYWORD,
}

#: Entity types that are themselves the answer to a claim of that kind.
_ENTITY_TO_CLAIM: dict[EntityType, ClaimKind] = {
    EntityType.EMAIL: ClaimKind.EMAIL,
    EntityType.USERNAME: ClaimKind.USERNAME,
    EntityType.PHONE: ClaimKind.PHONE,
    EntityType.DOMAIN: ClaimKind.DOMAIN,
    EntityType.HOST: ClaimKind.DOMAIN,
    EntityType.URL: ClaimKind.URL,
    EntityType.IP: ClaimKind.IP,
    EntityType.ORG: ClaimKind.ORG,
    EntityType.PERSON: ClaimKind.NAME,
}

#: What a candidate may *be*, given what the subject is.
#:
#: Without this, an ``employer=Cloudflare`` claim made Cloudflare itself the
#: second-ranked answer to "who is Matthew Prince" - it matched the claim
#: perfectly, because the claim names it. But an employer describes a
#: relationship the subject has, not an identity the subject could be, and a
#: company cannot be a person however well it scores.
_SUBJECT_TYPES: dict[str, frozenset[EntityType]] = {
    "person": frozenset({EntityType.PERSON, EntityType.USERNAME,
                         EntityType.EMAIL, EntityType.PHONE}),
    "org": frozenset({EntityType.ORG, EntityType.DOMAIN, EntityType.URL,
                      EntityType.PERSON}),
}

#: Claim kinds where holding two different values at once is ordinary rather
#: than contradictory. Someone can have four addresses and work two jobs; they
#: cannot have two dates of birth. Only the single-valued kinds can produce a
#: CONTRADICTS from a mere difference.
_MULTIVALUED = frozenset({
    ClaimKind.EMAIL, ClaimKind.USERNAME, ClaimKind.DOMAIN, ClaimKind.URL,
    ClaimKind.PHONE, ClaimKind.IP, ClaimKind.ROLE, ClaimKind.LANGUAGE,
    ClaimKind.SCHOOL, ClaimKind.KEYWORD, ClaimKind.NAME, ClaimKind.ORG,
})

#: Modules that can speak to each claim kind. Used only to tell UNKNOWN from
#: UNCHECKED: if every module that could have answered a claim failed or was
#: skipped, the claim was never tested and must not count against anybody.
_ANSWERED_BY: dict[ClaimKind, frozenset[str]] = {
    ClaimKind.BORN: frozenset({"wikidata"}),
    ClaimKind.COUNTRY: frozenset({"wikidata", "phone"}),
    ClaimKind.CITY: frozenset({"wikidata", "github", "social-graph", "bluesky"}),
    ClaimKind.ORG: frozenset({"wikidata", "github", "social-graph"}),
    ClaimKind.ROLE: frozenset({"wikidata", "github", "bluesky"}),
    ClaimKind.SCHOOL: frozenset({"wikidata"}),
    ClaimKind.LANGUAGE: frozenset({"wikidata", "github"}),
    ClaimKind.EMAIL: frozenset({"github", "gists", "packages", "keybase",
                                "social-graph", "wikidata"}),
    ClaimKind.USERNAME: frozenset({"username", "github", "keybase", "bluesky",
                                   "webfinger", "packages", "wikidata"}),
    ClaimKind.KEYWORD: frozenset({"github", "bluesky", "wikidata"}),
}


def _norm(text: str) -> str:
    return re.sub(r"[^\w\s]", " ", str(text or "").casefold()).strip()


def _words(text: str) -> set[str]:
    return {w for w in re.split(r"\s+", _norm(text)) if w}


def _untag(address: str) -> str:
    """``r.rafael+news@acme.com`` -> ``r.rafael@acme.com``.

    Tags are one mailbox handing out many addresses, so a tagged and an untagged
    form are the same person. The graph keeps them apart on purpose - how an
    address was handed out is evidence - but identity matching must not.
    """
    local, at, domain = address.partition("@")
    if not at:
        return address
    return f"{local.split('+')[0]}@{domain}"


def compare(claim: Claim, found: str) -> tuple[Verdict, str]:
    """Does *found* confirm, contradict or merely sit alongside the claim?

    Kept as one function per comparison style rather than a giant conditional,
    because the interesting decisions are all about *how loose* a match may be
    before it stops being evidence, and those differ by kind.
    """
    want = claim.value
    got = (found or "").strip()
    if not got:
        return Verdict.UNKNOWN, ""

    kind = claim.kind
    if kind is ClaimKind.EMAIL:
        return _exact(_untag(want), _untag(got.casefold()), kind)
    if kind in (ClaimKind.PHONE, ClaimKind.IP, ClaimKind.URL):
        return _exact(want, got.casefold(), kind)
    if kind is ClaimKind.USERNAME:
        # Handles are compared ignoring separators: "ryan.rafael" and
        # "ryan_rafael" on two platforms are one person far more often than
        # they are two, and the weight is low enough to carry that risk.
        return _exact(re.sub(r"[._-]", "", want),
                      re.sub(r"[._-]", "", got.casefold()), kind)
    if kind is ClaimKind.DOMAIN:
        if want == got.casefold():
            return Verdict.CONFIRMS, "same domain"
        if got.casefold().endswith("." + want) or want.endswith("." + got.casefold()):
            return Verdict.CONSISTENT, "one is a subdomain of the other"
        return Verdict.CONTRADICTS, "a different domain"
    if kind is ClaimKind.BORN:
        return _date(want, got)
    if kind in (ClaimKind.COUNTRY, ClaimKind.LANGUAGE):
        # Both sides through the same vocabulary. The claim was normalised when
        # it was added, but the source's spelling arrives raw, and "UK" against
        # a claim of "United Kingdom" shares no whole word - so without this the
        # two most common spellings of one country read as two countries.
        from .vocab import country as canon_country
        from .vocab import language as canon_language

        resolve_one = (canon_country if kind is ClaimKind.COUNTRY
                       else canon_language)
        return _textual(want, (resolve_one(got) or got), kind)
    if kind is ClaimKind.KEYWORD:
        # Absence of a keyword is never evidence against - people do not list
        # everything true of them - so this can only ever confirm.
        return ((Verdict.CONFIRMS, "mentioned") if _norm(want) in _norm(got)
                else (Verdict.UNKNOWN, ""))
    return _textual(want, got, kind)


def _exact(want: str, got: str, kind: ClaimKind) -> tuple[Verdict, str]:
    if want == got:
        return Verdict.CONFIRMS, "exact match"
    if kind in _MULTIVALUED:
        # Having a different one does not mean not having this one.
        return Verdict.UNKNOWN, ""
    return Verdict.CONTRADICTS, "a different value"


def _date(want: str, got: str) -> tuple[Verdict, str]:
    """Compare only as much of a date as both sides actually state.

    A brief that says "born 1971" and a profile that says "1971-04-02" agree.
    Requiring full equality would throw away the year-only case, which is the
    common one - people know roughly when someone was born far more often than
    they know the day.
    """
    a = re.findall(r"\d{4}-\d{2}-\d{2}|\d{4}", want)
    b = re.findall(r"\d{4}-\d{2}-\d{2}|\d{4}", got)
    if not a or not b:
        return Verdict.UNKNOWN, ""
    want_d, got_d = a[0], b[0]
    if len(want_d) == 4 or len(got_d) == 4:
        if want_d[:4] == got_d[:4]:
            return Verdict.CONSISTENT, "same year; one side gives only the year"
        return Verdict.CONTRADICTS, f"born {got_d[:4]}, not {want_d[:4]}"
    if want_d == got_d:
        return Verdict.CONFIRMS, "same date"
    return Verdict.CONTRADICTS, f"born {got_d}"


def _textual(want: str, got: str, kind: ClaimKind) -> tuple[Verdict, str]:
    """Names, places, employers: word-overlap, never edit distance.

    Edit distance makes "Yana" a near-match for "Iana" and an organisation
    called "Acme Health" a near-match for "Acme Wealth". What actually
    identifies these things is carrying the same words.
    """
    want_w, got_w = _words(want), _words(got)
    if not want_w or not got_w:
        return Verdict.UNKNOWN, ""
    if want_w == got_w:
        return Verdict.CONFIRMS, "exact match"
    if want_w <= got_w:
        return Verdict.CONSISTENT, "contains everything claimed"
    shared = want_w & got_w
    if shared:
        # Enough of a signal to show the reader, not enough to lean on.
        return Verdict.CONSISTENT, f"shares {', '.join(sorted(shared))}"
    if kind in _MULTIVALUED:
        return Verdict.UNKNOWN, ""
    return Verdict.CONTRADICTS, "nothing in common"


# ---------------------------------------------------------------------------
# clustering
# ---------------------------------------------------------------------------


class _Union:
    """Union-find over entity ids."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _clusters(inv: Investigation) -> dict[str, list[Any]]:
    """Group the graph's nodes into identities.

    Transitive closure over edges strong enough to mean "the same operator",
    which is how a Bluesky handle, its bare stem and a GitHub account sharing a
    key end up as one candidate instead of three competing ones that split the
    evidence between them.
    """
    graph = inv.graph
    if graph is None:
        return {}
    union = _Union()
    for node in graph:
        union.find(node.entity.eid)
    for edge in graph.edges.values():
        proves = any(ob.kind in _IDENTITY_EVIDENCE for ob in edge.observations)
        if proves or edge.label in _SAME_IDENTITY_RELATIONS:
            union.union(edge.src, edge.dst)

    out: dict[str, list[Any]] = {}
    for node in graph:
        out.setdefault(union.find(node.entity.eid), []).append(node)
    return out


# ---------------------------------------------------------------------------
# resolution
# ---------------------------------------------------------------------------


def resolve(inv: Investigation, brief: Brief, *, limit: int = 8) -> Resolution:
    """Rank the candidate identities against everything the brief asserts."""
    res = Resolution(subject=brief.label)
    if not brief:
        res.reading = ("no brief was given, so there is nothing to resolve "
                       "against - pass what you already know with --know")
        return res

    reachable = _reachable_modules(inv)
    res.untestable = sorted({
        f"{claim.kind.value}: no source in this scan could establish it"
        for claim in brief.claims
        if _ANSWERED_BY.get(claim.kind) is not None
        and not (_ANSWERED_BY[claim.kind] & reachable)
    })

    said = _assertions(inv)
    seeded = _seed_eids(inv, brief)
    candidates: list[Candidate] = []
    for members in _clusters(inv).values():
        # A cluster made only of the brief's own seeds is the question, not an
        # answer. Left in, the name you searched for sits at the top of its own
        # results matching every claim perfectly, because the claims are where
        # it came from - a tool agreeing with itself and calling it evidence.
        if all(n.entity.eid in seeded for n in members):
            continue
        cand = _candidate(members, brief, said, reachable)
        if cand is not None:
            candidates.append(cand)

    # Sort by the brief first and graph relevance second: a candidate the brief
    # supports is the answer to the user's question, and a candidate the graph
    # merely found a lot of is the answer to a different one.
    candidates.sort(key=lambda c: (-c.score, -c.relevance, c.label))
    res.candidates = candidates[:limit]
    res.reading = _reading(res, brief)
    res.next_check = _next_check(res, brief, reachable)
    return res


def _seed_eids(inv: Investigation, brief: Brief) -> set[str]:
    """Entity ids that exist only because the brief asserted them."""
    from .brief import SEEDABLE
    from .engine import entity_for

    out: set[str] = set()
    for claim in brief.seeds:
        ent = entity_for(claim.value, SEEDABLE[claim.kind])
        if ent is not None:
            out.add(ent.eid)
    return out


def _reachable_modules(inv: Investigation) -> set[str]:
    """Modules that actually ran and finished cleanly.

    Anything else could not have answered a claim, and a claim nobody could
    answer must not be scored as though the answer were no.
    """
    return {r.module for r in inv.results if r.status.is_complete}


def _assertions(inv: Investigation) -> dict[str, list[tuple[ClaimKind, str, str]]]:
    """``candidate name -> [(claim kind, stated value, module)]``.

    Read from the biography extraction, which already knows how to pull an
    employer out of whatever phrasing the module that found it happened to use,
    and already splits facts by which person they are about.
    """
    from .biography import extract as extract_bio

    out: dict[str, list[tuple[ClaimKind, str, str]]] = {}
    for subject in extract_bio(inv):
        bucket = out.setdefault(_norm(subject.name), [])
        for attr in subject.attributes:
            kind = _BIO_TO_CLAIM.get(attr.label)
            if kind is None:
                continue
            for value in attr.values:
                bucket.append((kind, value.text, value.source))
    return out


def _candidate(members: list[Any], brief: Brief,
               said: dict[str, list[tuple[ClaimKind, str, str]]],
               reachable: set[str]) -> Candidate | None:
    """Build one candidate from a cluster of graph nodes, and test the brief."""
    # The label comes from the most person-shaped member, so a cluster holding
    # a name and three handles is headed by the name.
    order = {EntityType.PERSON: 0, EntityType.ORG: 1, EntityType.USERNAME: 2,
             EntityType.EMAIL: 3, EntityType.DOMAIN: 4}
    ranked = sorted(members, key=lambda n: (order.get(n.entity.etype, 9),
                                            -n.score, n.entity.value))
    head = ranked[0]
    allowed = _SUBJECT_TYPES.get(brief.subject_kind)
    if allowed is not None and head.entity.etype not in allowed:
        return None

    cand = Candidate(
        label=head.entity.display,
        etype=head.entity.etype.value,
        members=[n.entity.display for n in ranked],
        relevance=max((n.score for n in members), default=0.0),
        sources=sorted({s for n in members for s in n.sources}),
    )

    # Everything this identity asserts about itself: values carried by its own
    # member entities, plus the biographical attributes filed under its name.
    stated: list[tuple[ClaimKind, str, str]] = []
    for node in members:
        kind = _ENTITY_TO_CLAIM.get(node.entity.etype)
        if kind is not None:
            stated.append((kind, node.entity.value,
                           ", ".join(sorted(node.sources)) or "graph"))
    for node in members:
        stated.extend(said.get(_norm(node.entity.value), []))

    for claim in brief.discriminators:
        cand.checks.append(_check(claim, stated, reachable, brief))
    return cand


def _check(claim: Claim, stated: list[tuple[ClaimKind, str, str]],
           reachable: set[str], brief: Brief) -> Check:
    """Test one claim against everything a candidate says about itself."""
    relevant = [(value, source) for kind, value, source in stated
                if kind is claim.kind]

    best: tuple[Verdict, str, str, str] | None = None
    rank = {Verdict.CONFIRMS: 4, Verdict.CONSISTENT: 3, Verdict.CONTRADICTS: 2,
            Verdict.UNKNOWN: 1, Verdict.UNCHECKED: 0}
    for value, source in relevant:
        verdict, why = compare(claim, value)
        if verdict is Verdict.UNKNOWN:
            continue
        if best is None or rank[verdict] > rank[best[0]]:
            best = (verdict, value, why, source)

    if best is None:
        # Nothing spoke to it. Which of the two silences is this?
        answerers = _ANSWERED_BY.get(claim.kind)
        if answerers is not None and not (answerers & reachable):
            return Check(claim=claim, verdict=Verdict.UNCHECKED, llr=0.0,
                         why="no source that could answer this ran cleanly")
        return Check(claim=claim, verdict=Verdict.UNKNOWN, llr=0.0,
                     why="nothing published either way")

    verdict, found, why, source = best
    power = claim.power
    base = power.confirm if verdict is not Verdict.CONTRADICTS else power.contradict
    llr = base * _WEIGHT[verdict]

    # A claim NOVA derived from another claim is not independent evidence of
    # anything. If the claim it came from also matched, this is the same
    # observation counted twice, so it contributes a fifth of its weight.
    if claim.derived and llr > 0:
        llr *= 0.2
        why = f"{why} (derived from the {claim.derived_from.value}, so barely counted)"
    return Check(claim=claim, verdict=verdict, found=found, llr=llr, why=why,
                 source=source)


def _reading(res: Resolution, brief: Brief) -> str:
    """One honest sentence about how much the leader can be trusted."""
    if not res.candidates:
        return "nothing this scan found could be matched against the brief"
    leader = res.candidates[0]
    if leader.score <= 0:
        return ("nothing here matches the brief; the strongest candidate is "
                "supported by none of it")
    strongest = max(leader.confirmed, key=lambda c: c.llr, default=None)
    margin = res.margin
    if leader.answered <= 1 and leader.score < 4.0:
        return (f"weak: {leader.label} matches on one thing only, and one "
                f"thing is what coincidence looks like")
    if margin < 1.0 and len(res.candidates) > 1:
        return (f"unresolved: {leader.label} and {res.candidates[1].label} are "
                f"supported almost equally, so the brief does not separate them")
    if strongest is not None and strongest.decisive:
        return (f"{leader.label} matches on {strongest.claim.kind.value}, which "
                f"is near-unique, plus {leader.answered - 1} other point(s); "
                f"next candidate is {margin:.1f} nats behind")
    return (f"{leader.label} leads on {leader.answered} matching point(s) but "
            f"nothing decisive; treat as a lead, not an identification")


def _next_check(res: Resolution, brief: Brief, reachable: set[str]) -> str:
    """The one fact that would do the most to settle it.

    Computed rather than suggested: among the claims the leading candidates
    have not answered, the one whose confirmation would move the score
    furthest. When two candidates are close, this is the difference between a
    report and an instruction.
    """
    if len(res.candidates) < 2:
        return ""
    top, second = res.candidates[0], res.candidates[1]
    #: kind -> (weight, who has not answered it). A claim only one of them has
    #: answered is the *most* useful thing to establish, not the least: it is
    #: already discriminating and one more data point would settle it.
    open_kinds: dict[ClaimKind, tuple[float, list[str]]] = {}
    for cand in (top, second):
        for check in cand.checks:
            if check.verdict not in (Verdict.UNKNOWN, Verdict.UNCHECKED):
                continue
            power = check.claim.power.confirm
            weight, who = open_kinds.get(check.claim.kind, (0.0, []))
            open_kinds[check.claim.kind] = (max(weight, power), [*who, cand.label])

    if open_kinds:
        kind, (power, who) = max(open_kinds.items(), key=lambda kv: kv[1][0])
        if power >= 1.0:
            names = " and ".join(who)
            return (f"establish the {kind.value} for {names}: it is worth "
                    f"{power:.1f} nats and "
                    + ("neither has published it"
                       if len(who) > 1 else "it is the gap between them"))

    # Nothing in the brief is left to test, so the useful advice is to widen it.
    missing = [k for k in (ClaimKind.PHONE, ClaimKind.EMAIL, ClaimKind.BORN,
                           ClaimKind.CITY, ClaimKind.ORG)
               if not brief.of(k)]
    if missing:
        names = ", ".join(k.value for k in missing[:3])
        return (f"the brief has nothing left to test; adding any of {names} "
                f"would separate the remaining candidates")
    return ""


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

_MARK = {
    Verdict.CONFIRMS: "++",
    Verdict.CONSISTENT: " +",
    Verdict.UNKNOWN: "  ",
    Verdict.UNCHECKED: " ?",
    Verdict.CONTRADICTS: "--",
}


def render_text(res: Resolution, *, detail: int = 3) -> str:
    """The resolution for a terminal. ``detail`` candidates get full workings."""
    if not res.candidates:
        return f"  {res.reading}"
    out = [f"  subject: {res.subject}", f"  {res.reading}", ""]
    for i, cand in enumerate(res.candidates):
        head = (f"  {i + 1}. {cand.label}  ({cand.etype})"
                f"   score {cand.score:+.1f}"
                f"   p={cand.probability:.2f}"
                f"   {cand.answered} of {len(cand.checks)} tested")
        out.append(head)
        if len(cand.members) > 1:
            out.append(f"       also: {', '.join(cand.members[1:6])}")
        if i < detail:
            for check in sorted(cand.checks, key=lambda c: -abs(c.llr)):
                if check.verdict is Verdict.UNKNOWN:
                    continue
                found = f" -> {check.found}" if check.found else ""
                out.append(f"       {_MARK[check.verdict]} "
                           f"{check.claim.kind.value:9} {check.claim.raw}{found}"
                           f"   [{check.llr:+.1f}] {check.why}")
        out.append("")
    if res.next_check:
        out.append(f"  what would settle it: {res.next_check}")
    if res.untestable:
        out.append("  nothing in this scan could test: "
                   + "; ".join(res.untestable))
    return "\n".join(out)


def render_markdown(res: Resolution, *, detail: int = 3) -> str:
    if not res.candidates:
        return f"*{res.reading}*\n"
    out = [f"**{res.reading}**", "",
           "| # | Candidate | Type | Score | p | Tested |",
           "|---|---|---|---|---|---|"]
    for i, cand in enumerate(res.candidates):
        out.append(f"| {i + 1} | {cand.label} | {cand.etype} "
                   f"| `{cand.score:+.1f}` | {cand.probability:.2f} "
                   f"| {cand.answered}/{len(cand.checks)} |")
    out.append("")
    for cand in res.candidates[:detail]:
        shown = [c for c in cand.checks if c.verdict is not Verdict.UNKNOWN]
        if not shown:
            continue
        out += [f"**{cand.label}** - the workings", "",
                "| | Claim | You said | It says | Weight | Why |",
                "|---|---|---|---|---|---|"]
        for check in sorted(shown, key=lambda c: -abs(c.llr)):
            out.append(f"| `{_MARK[check.verdict].strip() or '.'}` "
                       f"| {check.claim.kind.value} | {check.claim.raw} "
                       f"| {check.found or '-'} | `{check.llr:+.1f}` "
                       f"| {check.why} |")
        out.append("")
    if res.next_check:
        out += [f"> **What would settle it:** {res.next_check}", ""]
    if res.untestable:
        out += ["Nothing in this scan could test: "
                + "; ".join(res.untestable), ""]
    return "\n".join(out)


def render_json(res: Resolution) -> str:
    import json

    return json.dumps(res.to_dict(), indent=2, ensure_ascii=False)


__all__ = ["Candidate", "Check", "Resolution", "Verdict", "compare", "resolve",
           "render_json", "render_markdown", "render_text"]
