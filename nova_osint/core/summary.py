"""What the collection actually consists of, counted rather than asserted.

``281 findings`` is not a summary. It is a number that goes up when a scan
touches more sites, which is the one property a quality measure must not have.
A reader wants to know how much of that was *read off a source* as opposed to
computed by NOVA, how many genuinely independent sources are behind it, how
many relationships survived scoring, and how many things disagree.

The four classes
----------------

Every claim in an investigation belongs to exactly one of these, and the
distinction is about **how the claim came to exist**, never about how strong it
is. Strength is the log-odds table's job and is reported separately - an
``spki-shared`` link is ``INFERRED`` (nobody published "these two hosts are
related"; NOVA noticed one key in two certificates) *and* worth 6 nats. Those
are not in tension, and collapsing them is how a tool ends up treating its own
arithmetic as testimony.

``OBSERVED``
    Read directly off a source. A GitHub API field, a DNS answer, a link in a
    page's footer.

``DERIVED``
    Computed deterministically from something already held, with no new source
    consulted. ``improvised30`` from ``improvised30@gmail.com``.

``INFERRED``
    A relationship NOVA proposed by putting two or more observations beside
    each other. Every correlator output is here.

``UNVERIFIED``
    A lead that has been seen but not corroborated - a 200 from a profile page
    with nothing behind it, a search-engine snippet, a bare mention.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .acquisition import Method
from .models import Confidence, Investigation, ModuleStatus


class EvidenceClass(str, Enum):
    OBSERVED = "observed"
    DERIVED = "derived"
    INFERRED = "inferred"
    UNVERIFIED = "unverified"


#: Which class each kind of graph evidence belongs to.
#:
#: Exhaustive over :data:`nova_osint.core.graph.EVIDENCE` by construction, and
#: a test enforces it: a new evidence kind that nobody classified would
#: silently land in whatever the fallback is, and the fallback is the class a
#: reader trusts most. Adding a kind should cost one line here.
CLASS_BY_KIND: dict[str, EvidenceClass] = {
    # -- read off a source ---------------------------------------------------
    "keybase-proof": EvidenceClass.OBSERVED,
    "dnssec-ds-match": EvidenceClass.OBSERVED,
    "cert-san": EvidenceClass.OBSERVED,
    "commit-email": EvidenceClass.OBSERVED,
    "webfinger-proof": EvidenceClass.OBSERVED,
    "rdap-contact": EvidenceClass.OBSERVED,
    "whois-email": EvidenceClass.OBSERVED,
    "dns-a": EvidenceClass.OBSERVED,
    "dns-mx": EvidenceClass.OBSERVED,
    "dns-ns": EvidenceClass.OBSERVED,
    "reverse-dns": EvidenceClass.OBSERVED,
    "asn-announced": EvidenceClass.OBSERVED,
    "spf-include": EvidenceClass.OBSERVED,
    "dmarc-rua": EvidenceClass.OBSERVED,
    "dmarc-ruf": EvidenceClass.OBSERVED,
    "profile-email": EvidenceClass.OBSERVED,
    "profile-link": EvidenceClass.OBSERVED,
    "declared-account": EvidenceClass.OBSERVED,
    "linked-account": EvidenceClass.OBSERVED,
    "site-owner": EvidenceClass.OBSERVED,
    "declared-employer": EvidenceClass.OBSERVED,
    "key-uid": EvidenceClass.OBSERVED,
    "published-contact": EvidenceClass.OBSERVED,
    "passive-dns": EvidenceClass.OBSERVED,
    "corporate-officer": EvidenceClass.OBSERVED,
    "wikidata-claim": EvidenceClass.OBSERVED,
    "org-member": EvidenceClass.OBSERVED,
    "co-author": EvidenceClass.OBSERVED,
    "mutual-follow": EvidenceClass.OBSERVED,
    "social-follow": EvidenceClass.OBSERVED,
    "document-author": EvidenceClass.OBSERVED,
    "gravatar-hash": EvidenceClass.OBSERVED,
    "handle-verified": EvidenceClass.OBSERVED,
    "control-handle-matched": EvidenceClass.OBSERVED,
    "explicit-denial": EvidenceClass.OBSERVED,
    "parked-domain": EvidenceClass.OBSERVED,
    # -- computed from what we already had -----------------------------------
    "email-domain": EvidenceClass.DERIVED,
    "subdomain-of": EvidenceClass.DERIVED,
    "handle-derived": EvidenceClass.DERIVED,
    "pivot-derived": EvidenceClass.DERIVED,
    # -- NOVA put two observations side by side ------------------------------
    "key-fingerprint-shared": EvidenceClass.INFERRED,
    "spki-shared": EvidenceClass.INFERRED,
    "tracker-id-shared": EvidenceClass.INFERRED,
    "co-maintainer": EvidenceClass.INFERRED,
    "favicon-hash": EvidenceClass.INFERRED,
    "page-structure-hash": EvidenceClass.INFERRED,
    "stylometry-match": EvidenceClass.INFERRED,
    "timezone-agreement": EvidenceClass.INFERRED,
    "name-similarity": EvidenceClass.INFERRED,
    "shared-hosting": EvidenceClass.INFERRED,
    "looks-like": EvidenceClass.INFERRED,
    # -- seen, not corroborated ----------------------------------------------
    "handle-unverified": EvidenceClass.UNVERIFIED,
    "search-result": EvidenceClass.UNVERIFIED,
    "mentioned": EvidenceClass.UNVERIFIED,
}

#: Fallback for an evidence kind nobody classified. ``UNVERIFIED`` on purpose:
#: the failure mode of guessing wrong should be a claim that reads weaker than
#: it is, never one that reads stronger.
UNKNOWN_KIND = EvidenceClass.UNVERIFIED


def classify_kind(kind: str) -> EvidenceClass:
    return CLASS_BY_KIND.get(kind, UNKNOWN_KIND)


def classify_finding(finding: Any) -> EvidenceClass:
    """Which class one ``Finding`` belongs to.

    Three signals, in order of how much they actually know:

    The acquisition method, when the module stamped one. ``LOCAL`` means it was
    computed on this machine from data already held, which is the definition of
    derived; ``SEARCH`` means a third party's index said so, which is a lead.

    Then the confidence. ``POSSIBLE`` is NOVA's existing word for "weak or
    ambiguous", and a weak claim with no corroboration is exactly
    ``UNVERIFIED``.

    Otherwise it was read off a source, which is the common case and the one
    the collectors were built for.
    """
    acquisition = getattr(finding, "acquisition", None)
    if acquisition is not None:
        if acquisition.method is Method.LOCAL:
            return EvidenceClass.DERIVED
        if acquisition.method is Method.SEARCH:
            return EvidenceClass.UNVERIFIED
    if getattr(finding, "confidence", None) is Confidence.POSSIBLE:
        return EvidenceClass.UNVERIFIED
    return EvidenceClass.OBSERVED


# ---------------------------------------------------------------------------
# the summary
# ---------------------------------------------------------------------------

#: An edge at or above this is reported as a relationship NOVA stands behind
#: rather than a candidate. 3.5 nats is the Admiralty ``B`` boundary already
#: used by :func:`nova_osint.core.graph.admiralty`, so the two never disagree.
STRONG_NATS = 3.5


@dataclass
class EvidenceSummary:
    """Counted facts about a collection. Every field is computed, none guessed."""

    observations: int = 0
    by_class: dict[str, int] = field(default_factory=dict)
    #: Distinct ``Observation.independence`` values across the whole graph -
    #: module plus the host it read, or an explicit group. The honest answer to
    #: "how many people told you this", and usually far below the finding count.
    independent_sources: int = 0
    #: Relationships at or above :data:`STRONG_NATS` after every discount.
    strong_relationships: int = 0
    #: Positive but below the bar: real leads, not conclusions.
    candidate_relationships: int = 0
    #: Edges whose combined evidence is negative - argued against, kept anyway.
    negative_relationships: int = 0
    entities: int = 0
    contradictions: dict[str, int] = field(default_factory=dict)
    #: ``{status: n}`` over every module that ran, plus those that never did.
    modules: dict[str, int] = field(default_factory=dict)
    modules_total: int = 0
    findings: int = 0
    #: Leads found and deliberately not followed, by which rule stopped them.
    declined: dict[str, int] = field(default_factory=dict)

    @property
    def claims(self) -> int:
        """Everything classified: findings plus graph observations.

        The two are counted together because they are the same kind of thing
        for this purpose - somebody asserting something - and separately
        elsewhere because they are stored differently. What matters is that
        the class breakdown sums to *this*, not to either half: a block of
        four numbers printed under a heading that names a smaller total is a
        table a reader cannot reconcile and will stop trusting.
        """
        return self.findings + self.observations

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": self.findings,
            "observations": self.observations,
            "claims": self.claims,
            "by_class": self.by_class,
            "independent_sources": self.independent_sources,
            "entities": self.entities,
            "relationships": {
                "strong": self.strong_relationships,
                "candidate": self.candidate_relationships,
                "negative": self.negative_relationships,
            },
            "contradictions": self.contradictions,
            "modules": {"total": self.modules_total, **self.modules},
            "declined": self.declined,
        }

    def lines(self) -> list[str]:
        """The summary as a reader sees it, one statement per line."""
        out = [
            f"Findings: {self.findings}",
            f"Observations on the graph: {self.observations}",
            f"Claims by class ({self.claims} in total):",
        ]
        for cls in EvidenceClass:
            out.append(f"  {cls.value}: {self.by_class.get(cls.value, 0)}")
        out += [
            f"Independent sources: {self.independent_sources}",
            f"Entities: {self.entities}",
            f"Strong relationships: {self.strong_relationships}",
            f"Candidate relationships: {self.candidate_relationships}",
            f"Relationships argued against: {self.negative_relationships}",
            f"Contradictions: {self.contradictions.get('total', 0)}"
            f" ({self.contradictions.get('high', 0)} high)",
            f"Modules: {self.modules_total} total, "
            + ", ".join(f"{n} {status}" for status, n in sorted(self.modules.items())),
        ]
        if self.declined:
            out.append("Leads declined: "
                       + ", ".join(f"{n} {why}" for why, n in sorted(self.declined.items())))
        return out


def build(inv: Investigation, contradictions: list[Any] | None = None
          ) -> EvidenceSummary:
    """Count one investigation.

    ``contradictions`` is passed in rather than detected here so a caller that
    has already run the detector does not pay for it twice; omitted, it is
    computed.
    """
    if contradictions is None:
        from .contradictions import detect

        contradictions = detect(inv)
    from .contradictions import counts as contradiction_counts

    summary = EvidenceSummary()
    summary.findings = len(inv.findings)
    summary.contradictions = contradiction_counts(contradictions)

    by_class: dict[str, int] = {c.value: 0 for c in EvidenceClass}
    for finding in inv.findings:
        by_class[classify_finding(finding).value] += 1

    graph = inv.graph
    if graph is not None:
        sources: set[str] = set()
        for edge in graph.edges.values():
            llr = edge.llr
            if llr >= STRONG_NATS:
                summary.strong_relationships += 1
            elif llr > 0:
                summary.candidate_relationships += 1
            else:
                summary.negative_relationships += 1
            for ob in edge.observations:
                summary.observations += 1
                sources.add(ob.independence)
                by_class[classify_kind(ob.kind).value] += 1
        summary.independent_sources = len(sources)
        summary.entities = len(graph)
    else:
        # No graph: the findings are all we have, and their modules are the
        # only source count available. Stated rather than left at zero, which
        # would read as "no sources" instead of "not graphed".
        summary.independent_sources = len({r.module for r in inv.results
                                           if r.findings})
    summary.by_class = by_class

    statuses: dict[str, int] = {}
    for result in inv.results:
        statuses[result.status.value] = statuses.get(result.status.value, 0) + 1
    if inv.skipped:
        statuses[ModuleStatus.SKIPPED.value] = (
            statuses.get(ModuleStatus.SKIPPED.value, 0) + len(inv.skipped))
    summary.modules = statuses
    summary.modules_total = len(inv.results) + len(inv.skipped)

    declined: dict[str, int] = {}
    for _lead, why in inv.not_followed:
        declined[why] = declined.get(why, 0) + 1
    if inv.expansion is not None:
        if getattr(inv.expansion, "below_floor", None):
            declined["too weakly evidenced"] = len(inv.expansion.below_floor)
        if getattr(inv.expansion, "ruled_out", None):
            declined["ruled out"] = len(inv.expansion.ruled_out)
    summary.declined = declined
    return summary
