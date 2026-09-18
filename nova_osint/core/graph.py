"""The entity graph: what connects to what, how strongly, and on what evidence.

This is the piece that turns a list of scans into an investigation. Modules stop
being "things that print facts about a target" and become **transforms**: given
an entity, emit findings, new entities, and edges between them. The engine then
walks outward from the seed instead of running one flat pass.

Everything below exists to solve the one problem that kills naive expansion:

    Follow every link and you drown. A domain resolves to a Cloudflare address
    that answers for four million other names; two hops later the graph is the
    internet and the target is gone.

So the graph is weighted, and three separate ideas do the weighting:

**1. Evidence strength, in log-odds.** An edge does not carry "likely". It
carries a log-likelihood ratio - how much more probable this observation is if
the link is real than if it is not. Log-odds are used because independent
evidence then *adds*: a shared tracker id (+5.0) plus a matching handle (+0.4)
is +5.4, and :func:`probability` converts back to a number a human can read.
Disconfirming evidence is simply negative, which is how the existing username
control-handle check generalises to everything else.

**2. Specificity, from observed population.** An edge through something rare is
worth more than an edge through something common. One certificate covering two
names links them; a shared nameserver at a host with 50,000 customers links
nobody. :func:`Edge.effective_llr` divides the raw strength by the log of the
hub's degree, so hubs demote themselves automatically as the scan discovers how
big they are - no hand-maintained list of "ignore Cloudflare".

**3. Relevance decay from the seed.** A node's score is the best path back to
the seed, multiplying decayed edge confidences. The frontier is a priority queue
over that score, so the engine spends its request budget on the most-connected
part of the graph first and a budget cut-off truncates the *least* relevant work
rather than whatever happened to be last in the list.

Stdlib only, no clock, no I/O: the graph is a pure data structure so it can be
rebuilt identically from the store and diffed between runs.
"""

from __future__ import annotations

import heapq
import math
from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from .entities import Entity, EntityType

# ---------------------------------------------------------------------------
# evidence weights
# ---------------------------------------------------------------------------

#: Log-likelihood ratio, in nats, for each kind of evidence we know how to
#: produce. These are judgements, not measurements, and they are collected in
#: one table so they can be argued with, tuned, and tested - rather than being
#: scattered through fifteen modules as magic "confidence=LIKELY" calls.
#:
#: Calibration anchors used when picking the numbers:
#:   +7  practically certain: a private key would have to be shared to fake it
#:   +5  strong: a deliberate act by the same operator (an account, a pixel id)
#:   +3  good: an authoritative record naming both sides
#:   +1  suggestive: consistent with the link, also consistent with coincidence
#:    0  no information
#:   -3  disconfirming: the observation argues against the link
EVIDENCE: dict[str, float] = {
    # cryptographic / operator-controlled -----------------------------------
    "key-fingerprint-shared": 7.5,   # same SSH/GPG key on both identities
    "spki-shared": 6.0,              # same public key across certificates
    "keybase-proof": 6.0,            # signed statement linking two accounts
    "dnssec-ds-match": 5.0,
    "tracker-id-shared": 5.0,        # same GA / Pixel / AdSense property
    "cert-san": 4.5,                 # names on one certificate
    "gravatar-hash": 4.5,            # email hash resolves to a profile
    "commit-email": 4.0,             # author email in a pushed commit
    "webfinger-proof": 4.0,
    # authoritative records --------------------------------------------------
    "rdap-contact": 3.5,
    "whois-email": 3.5,
    "dns-a": 3.0,                    # demoted by hub degree, see effective_llr
    "dns-mx": 2.5,
    "dns-ns": 1.5,
    "reverse-dns": 2.5,
    "asn-announced": 2.0,
    "subdomain-of": 3.0,
    "spf-include": 2.0,
    "dmarc-rua": 2.0,            # where a domain sends its DMARC reports
    "dmarc-ruf": 2.0,            # and its forensic ones, which carry messages
    "email-domain": 3.0,         # the domain half of an address
    "profile-email": 3.5,        # an address the account holder published
    "profile-link": 1.5,         # a link someone put on their own profile
    "key-uid": 5.0,              # identity baked into a published public key
    "published-contact": 3.0,    # security.txt and friends
    "passive-dns": 2.0,          # historic resolution, demoted by hub degree
    # -- people and relationships -------------------------------------------
    "corporate-officer": 4.0,    # named as CEO/founder/director of an entity
    "wikidata-claim": 3.0,       # curated statement; good, and editable by anyone
    "org-member": 2.5,           # public, opt-in membership of an organisation
    "co-maintainer": 2.0,        # both publish the same package
    "co-author": 2.5,            # Co-authored-by on the same commit
    "mutual-follow": 1.0,        # they follow each other: a relationship
    "social-follow": 0.3,        # one-way: an interest, not a relationship
    # behavioural / fingerprint ---------------------------------------------
    "favicon-hash": 2.5,
    "page-structure-hash": 2.0,
    #: The document's own properties name this person. Strong, because it
    #: records an account that was logged in when the file was saved -
    #: and short of proof, because templates, shared machines and
    #: conversion services all put somebody else's name in the field.
    "document-author": 1.8,
    "stylometry-match": 1.5,
    "timezone-agreement": 0.6,
    # weak string-level ------------------------------------------------------
    "handle-verified": 1.5,          # profile confirmed, control handle failed
    "handle-unverified": 0.4,        # 200 response, nothing more
    "handle-derived": 0.3,           # generated alias, e.g. dots stripped
    "name-similarity": 0.2,
    #: A search engine's index contains a page whose URL names this handle.
    #: Weaker than a 200 from the profile itself, because an index entry is a
    #: third party's recollection of a page that may no longer exist, and the
    #: query that surfaced it was written by us. It is a lead worth following,
    #: never a link worth asserting.
    "search-result": 0.25,
    "shared-hosting": 0.05,          # kept for the record, deliberately tiny
    # disconfirming ----------------------------------------------------------
    "control-handle-matched": -3.0,  # the site says yes to everyone
    "parked-domain": -1.0,
    "explicit-denial": -4.0,
    # structural, not evidential --------------------------------------------
    "looks-like": 0.0,               # typosquat: a finding, not a link
    "mentioned": 0.1,
    #: A legacy ``result.pivot()`` with no stated evidence. Modules only pivot
    #: on something they actually found, so it is worth following - but it is
    #: deliberately weaker than any typed evidence, so a module that upgrades to
    #: ``result.entity(..., evidence=...)`` is rewarded with a better score.
    "pivot-derived": 1.2,
}

#: Edges we never expand through, whatever they score. A typosquat neighbour is
#: worth reporting and worth *not* crawling: it is someone else's domain and
#: pivoting into it silently widens the investigation onto a third party.
NO_EXPAND = frozenset({"looks-like", "control-handle-matched", "explicit-denial"})

#: Above this many neighbours a node is infrastructure, not an identity. It is a
#: soft threshold: :meth:`EntityGraph.specificity` decays smoothly, this only
#: decides when to stop expanding *through* it.
HUB_DEGREE = 12


def probability(llr: float) -> float:
    """Log-odds to a 0-1 probability. Clamped: nothing here is ever certain.

    The input is clamped before the exponential, not after: a module that adds
    up two hundred observations produces an ``llr`` that overflows ``math.exp``,
    and a scan should not die because something was *very* well corroborated.
    """
    return min(0.999, max(0.001, 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, llr))))))


def transmittance(llr: float) -> float:
    """How much relevance an edge passes along, 0-1.

    Not the same thing as the edge's probability, and conflating the two was the
    first version of this file's bug. An edge with no evidence either way sits
    at probability 0.5, and propagating half the parent's relevance through a
    link we have no reason to believe is how a weak one-hop guess out-scores a
    cryptographically proven three-hop chain.

    What actually propagates is how far the edge moves belief *above chance*, so
    a no-information edge transmits nothing and only real evidence extends the
    walk.
    """
    return max(0.0, 2.0 * (probability(llr) - 0.5))


def admiralty(llr: float, corroborations: int) -> str:
    """NATO Admiralty grade, e.g. ``B2``.

    Two axes, because they are genuinely different questions and collapsing them
    is how reports end up asserting a rumour with the confidence of a registry
    record. The letter is how much we trust the *strongest source*; the digit is
    how well the claim is *corroborated* by independent ones.
    """
    letter = "A" if llr >= 6 else "B" if llr >= 3.5 else "C" if llr >= 1.5 else "D" if llr > 0 else "E"
    digit = "1" if corroborations >= 3 else "2" if corroborations == 2 else "3" if corroborations == 1 else "5"
    if llr <= -1:
        return "E5"
    return letter + digit


# ---------------------------------------------------------------------------
# edges
# ---------------------------------------------------------------------------


@dataclass
class Observation:
    """One reason to believe an edge. Never overwritten, only appended.

    Keeping observations separate from the edge is what makes the graph
    defensible: an analyst can ask "why do you say these are the same person"
    and get back the four specific requests that caused it, each with the module
    that made it and the URL it came from.
    """

    kind: str
    module: str
    url: str | None = None
    detail: str = ""
    #: sha256 of the stored response body, when the evidence store has it.
    evidence: str | None = None
    #: Overrides the EVIDENCE table when a module can be more precise.
    llr: float | None = None

    @property
    def strength(self) -> float:
        if self.llr is not None:
            return self.llr
        return EVIDENCE.get(self.kind, 0.1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind, "module": self.module, "url": self.url,
            "detail": self.detail, "evidence": self.evidence,
            "llr": round(self.strength, 3),
        }


@dataclass
class Edge:
    src: str
    dst: str
    label: str
    observations: list[Observation] = field(default_factory=list)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.src, self.dst, self.label)

    @property
    def llr(self) -> float:
        """Combined strength of every observation on this edge.

        Independent observations add - that is the whole reason for working in
        log-odds. But two observations of the *same kind* are usually not
        independent (crt.sh and CertSpotter read the same CT logs), so repeats
        of a kind are discounted geometrically rather than summed outright.
        """
        by_kind: dict[str, list[float]] = defaultdict(list)
        for ob in self.observations:
            by_kind[ob.kind].append(ob.strength)
        total = 0.0
        for strengths in by_kind.values():
            strengths.sort(key=abs, reverse=True)
            for i, s in enumerate(strengths):
                total += s * (0.5 ** i)
        return total

    @property
    def corroborations(self) -> int:
        """How many *distinct* kinds of evidence support this edge."""
        return len({ob.kind for ob in self.observations if ob.strength > 0})

    @property
    def probability(self) -> float:
        return probability(self.llr)

    @property
    def grade(self) -> str:
        return admiralty(self.llr, self.corroborations)

    def effective_llr(self, hub_degree: int) -> float:
        """Strength after demoting the edge for passing through a hub.

        ``hub_degree`` is the degree of the busier endpoint. A link through a
        node with two neighbours keeps its full weight; through one with two
        hundred it keeps about a third. Positive evidence only - disconfirming
        evidence is not weakened by the hub being popular.
        """
        if self.llr <= 0 or hub_degree <= 2:
            return self.llr
        return self.llr / (1.0 + math.log(hub_degree / 2.0))

    def to_dict(self) -> dict[str, Any]:
        return {
            "src": self.src, "dst": self.dst, "label": self.label,
            "llr": round(self.llr, 3), "probability": round(self.probability, 3),
            "grade": self.grade,
            "observations": [o.to_dict() for o in self.observations],
        }


# ---------------------------------------------------------------------------
# the graph
# ---------------------------------------------------------------------------


@dataclass
class Node:
    entity: Entity
    #: Relevance to the seed, 0-1. Set by :meth:`EntityGraph.rescore`.
    score: float = 0.0
    #: Hops from the seed along the best-scoring path.
    depth: int = 0
    #: Has a transform already run against this entity?
    expanded: bool = False
    #: Module names that produced or touched it, for provenance.
    sources: set[str] = field(default_factory=set)
    first_seen: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        d = self.entity.to_dict()
        d.update(score=round(self.score, 4), depth=self.depth,
                 expanded=self.expanded, sources=sorted(self.sources))
        return d


class EntityGraph:
    """Nodes, weighted edges, and the scoring that decides what to look at next.

    Not thread-safe by design: the engine owns one graph and merges module
    output into it from the collecting thread. Modules never touch it directly,
    which keeps the locking story to "there isn't one".
    """

    def __init__(self, seed: Entity | None = None) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: dict[tuple[str, str, str], Edge] = {}
        self._adj: dict[str, set[str]] = defaultdict(set)
        self.seed: str | None = None
        if seed is not None:
            self.seed = self.add(seed, score=1.0).entity.eid

    # -- construction --------------------------------------------------------

    def add(self, entity: Entity, *, source: str = "", score: float = 0.0,
            depth: int = 0, when: float = 0.0) -> Node:
        """Insert or merge an entity. Returns the live node either way.

        Merging keeps the *better* provenance: the shallower depth, the higher
        score, and the union of sources. A node discovered twice by two modules
        is stronger evidence than one discovered once, and losing that on the
        second insert would silently throw away corroboration.
        """
        node = self.nodes.get(entity.eid)
        if node is None:
            node = Node(entity, score=score, depth=depth, first_seen=when)
            self.nodes[entity.eid] = node
        else:
            node.score = max(node.score, score)
            node.depth = min(node.depth, depth) if node.depth else depth
            node.entity.attrs.update(entity.attrs)
        if source:
            node.sources.add(source)
        return node

    def connect(self, src: Entity, dst: Entity, label: str, observation: Observation,
                *, source: str = "") -> Edge:
        """Add an observation linking two entities, creating both if needed."""
        s = self.add(src, source=source or observation.module)
        d = self.add(dst, source=source or observation.module)
        key = (s.entity.eid, d.entity.eid, label)
        edge = self.edges.get(key)
        if edge is None:
            edge = Edge(s.entity.eid, d.entity.eid, label)
            self.edges[key] = edge
            self._adj[s.entity.eid].add(d.entity.eid)
            self._adj[d.entity.eid].add(s.entity.eid)
        # Identical observations arrive whenever a module reruns over a cached
        # response; appending them would inflate the edge for free.
        sig = (observation.kind, observation.module, observation.url, observation.detail)
        if not any((o.kind, o.module, o.url, o.detail) == sig for o in edge.observations):
            edge.observations.append(observation)
        return edge

    # -- topology ------------------------------------------------------------

    def degree(self, eid: str) -> int:
        return len(self._adj.get(eid, ()))

    def neighbors(self, eid: str) -> set[str]:
        return set(self._adj.get(eid, ()))

    def edges_of(self, eid: str) -> list[Edge]:
        return [e for e in self.edges.values() if e.src == eid or e.dst == eid]

    def between(self, a: str, b: str) -> list[Edge]:
        return [e for e in self.edges.values()
                if {e.src, e.dst} == {a, b}]

    def specificity(self, eid: str) -> float:
        """0-1: how much an edge through this node is worth.

        Purely structural - it is derived from what the scan has actually
        observed, so it needs no allowlist and it improves as the graph grows.
        A node seen once is fully specific; a node with fifty neighbours is
        infrastructure and is worth almost nothing as a connector.
        """
        deg = self.degree(eid)
        if deg <= 1:
            return 1.0
        return 1.0 / (1.0 + math.log(deg))

    # -- scoring -------------------------------------------------------------

    def rescore(self, *, decay: float = 0.55) -> None:
        """Recompute every node's relevance to the seed.

        A widest-path search (Dijkstra with max-product relaxation instead of
        min-sum): a node's score is the strongest chain of belief connecting it
        back to the seed, not the shortest hop count. That is the difference
        between "three links away" and "three links away through evidence that
        is 97%, 95% and 91% good" - only the second deserves a request budget.

        ``decay`` is the per-hop tax. Without it a long chain of near-certain
        edges would keep full relevance forever and the frontier would wander
        off the target; at 0.55 a fourth hop has to be exceptional to outrank an
        unexpanded second hop.
        """
        for node in self.nodes.values():
            node.score = 0.0
            node.depth = 0
        if not self.seed or self.seed not in self.nodes:
            return
        self.nodes[self.seed].score = 1.0

        # heapq is a min-heap; negate to pop the strongest path first.
        heap: list[tuple[float, int, str]] = [(-1.0, 0, self.seed)]
        settled: set[str] = set()
        while heap:
            neg, depth, eid = heapq.heappop(heap)
            if eid in settled:
                continue
            settled.add(eid)
            score = -neg
            node = self.nodes[eid]
            node.score, node.depth = score, depth
            for other in self._adj[eid]:
                if other in settled:
                    continue
                hub = max(self.degree(eid), self.degree(other))
                best = max((e.effective_llr(hub) for e in self.between(eid, other)),
                           default=0.0)
                if best <= 0:
                    continue
                candidate = score * transmittance(best) * decay
                if candidate > self.nodes[other].score and candidate > 1e-4:
                    self.nodes[other].score = candidate
                    heapq.heappush(heap, (-candidate, depth + 1, other))

    # -- frontier ------------------------------------------------------------

    def frontier(self, *, min_score: float = 0.02, max_depth: int = 3,
                 types: Iterable[EntityType] | None = None) -> list[Node]:
        """Unexpanded nodes worth spending requests on, best first.

        Both limits are real limits, not suggestions. ``max_depth`` bounds the
        shape of the walk and ``min_score`` bounds its quality; the engine adds
        a third bound on total requests. Any one of them alone can be defeated
        by a graph that is broad rather than deep, which is the normal shape for
        a domain with a thousand certificate names.
        """
        allowed = set(types) if types else None
        out = [
            n for n in self.nodes.values()
            if not n.expanded
            and n.entity.etype.lookupable
            and n.score >= min_score
            and n.depth <= max_depth
            and (allowed is None or n.entity.etype in allowed)
            and not self._only_reachable_by_dead_edges(n.entity.eid)
        ]
        out.sort(key=lambda n: (-n.score, n.depth, n.entity.eid))
        return out

    def _only_reachable_by_dead_edges(self, eid: str) -> bool:
        """True when every path here is one we refuse to expand through."""
        edges = self.edges_of(eid)
        if not edges:
            return False
        return all(e.label in NO_EXPAND for e in edges)

    def hubs(self, threshold: int = HUB_DEGREE) -> list[Node]:
        """Nodes busy enough to be shared infrastructure. Reported, not crawled."""
        return sorted((n for n in self.nodes.values() if self.degree(n.entity.eid) >= threshold),
                      key=lambda n: -self.degree(n.entity.eid))

    # -- queries -------------------------------------------------------------

    def of_type(self, etype: EntityType) -> list[Node]:
        return [n for n in self.nodes.values() if n.entity.etype is etype]

    def path(self, target: str) -> list[str]:
        """The chain of entities from the seed to ``target``, for the report.

        Rebuilt greedily from the scores rather than stored during the search:
        cheap, and it cannot go stale when an edge is added afterwards. Returns
        ``[]`` when nothing connects.
        """
        if not self.seed or target not in self.nodes:
            return []
        chain, cur, guard = [target], target, 0
        while cur != self.seed and guard < 64:
            guard += 1
            best, best_score = None, -1.0
            for other in self._adj[cur]:
                n = self.nodes[other]
                if n.score > best_score and n.depth < self.nodes[cur].depth:
                    best, best_score = other, n.score
            if best is None:
                return []
            chain.append(best)
            cur = best
        return list(reversed(chain))

    def __len__(self) -> int:
        return len(self.nodes)

    def __iter__(self) -> Iterator[Node]:
        return iter(self.nodes.values())

    def to_dict(self, *, min_score: float = 0.0) -> dict[str, Any]:
        keep = {eid for eid, n in self.nodes.items() if n.score >= min_score}
        return {
            "seed": self.seed,
            "nodes": [n.to_dict() for eid, n in self.nodes.items() if eid in keep],
            "edges": [e.to_dict() for e in self.edges.values()
                      if e.src in keep and e.dst in keep],
            "summary": {
                "entities": len(keep),
                "edges": sum(1 for e in self.edges.values()
                             if e.src in keep and e.dst in keep),
                "hubs": len(self.hubs()),
                "by_type": {
                    t.value: sum(1 for eid in keep
                                 if self.nodes[eid].entity.etype is t)
                    for t in EntityType
                    if any(self.nodes[eid].entity.etype is t for eid in keep)
                },
            },
        }
