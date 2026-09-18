"""The evidence model: one value, who said it, and how much that is worth.

Every other layer in this project answers "what did we find". This one answers
the question underneath it - **how do we hold two sources that disagree** -
because a biographical dossier is the first output here where disagreement is
the normal case rather than a bug.

A scan of a domain rarely has two opinions about its MX record. A scan of a
*person* routinely has three opinions about their employer, because one source
is a stale profile, one is a conference bio from 2019, and one is current. The
old flat renderers dealt with this by printing all three in different sections
and letting the reader notice. That is not good enough for a dossier, whose
whole promise is one consolidated answer.

The three rules
---------------

**Never silently overwrite.** When two sources give different values for a
single-valued field, both survive, both keep their source, and they are ordered
by confidence. The reader sees a ranked disagreement, not a winner. Picking one
and deleting the other is how a tool launders a guess into a fact.

**Confidence is a property of the source, not of the value.** A date of birth
is not more true because it is more specific. ``SOURCE_WEIGHTS`` is the single
place that decides what a kind of source is worth, so the number attached to a
value can always be traced to a policy rather than to a vibe.

**De-duplication merges provenance, it does not discard it.** Two sources
agreeing on one value is the single most valuable signal in the whole system,
so the merged record keeps *both* names. Collapsing them to one source throws
away exactly the thing corroboration means.

This module is deliberately free of any import from the rest of the package, so
it can be unit-tested and reused without dragging the engine in.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# what a kind of source is worth
# ---------------------------------------------------------------------------

#: How much to trust a class of source, 0.0 - 1.0.
#:
#: These are *policy*, not measurements, which is why they live in one dict
#: instead of being sprinkled through the modules. Change a number here and
#: every dossier re-ranks consistently.
#:
#: ``user_provided`` is 1.00 because the user asserting something is the one
#: input this tool is not entitled to second-guess - it is the brief, not a
#: finding. ``synthetic_fixture`` is deliberately low and deliberately *named*:
#: a value carrying it is test data and must never read as a discovery.
SOURCE_WEIGHTS: dict[str, float] = {
    "user_provided": 1.00,
    "verified_public_record": 0.90,
    "official_profile": 0.90,
    "professional_api": 0.85,
    "public_web_profile": 0.70,
    "synthetic_fixture": 0.60,
    "historical_forum": 0.50,
    "derived": 0.30,
}

#: The default when a source class is not in the table. Low on purpose: an
#: unclassified source should look weak, not average.
UNKNOWN_WEIGHT = 0.40

#: Evidence types that are *not* real-world observations. A dossier containing
#: one of these is a development or demo artefact, and every renderer marks it
#: loudly. Nothing in this set may ever be promoted by corroboration.
SYNTHETIC_TYPES = frozenset({"synthetic_fixture"})

#: Corroboration bonus per *additional independent* source, and the ceiling it
#: may reach. Two sources agreeing is strong; five sources agreeing is not five
#: times stronger, and a value must never reach certainty by repetition alone.
CORROBORATION_STEP = 0.05
CORROBORATION_CAP = 0.97


def weight_for(evidence_type: str) -> float:
    """What one observation of this kind is worth before corroboration."""
    return SOURCE_WEIGHTS.get(evidence_type, UNKNOWN_WEIGHT)


# ---------------------------------------------------------------------------
# normalisation
# ---------------------------------------------------------------------------

_SPACE = re.compile(r"\s+")
#: Trailing noise that routinely differs between sources describing one thing:
#: "Acme Global Solutions, Inc." and "Acme Global Solutions" are one employer.
_CORPORATE_SUFFIX = re.compile(
    r"[\s,]+(inc|inc\.|llc|l\.l\.c\.|ltd|ltd\.|limited|corp|corp\.|corporation"
    r"|co|co\.|gmbh|s\.a\.|sa|plc|pty|bv|nv|ab|oy|as)\.?$", re.I)


def normalise(text: str, *, corporate: bool = False) -> str:
    """A comparison key for *text* - lowercase, unaccented, single-spaced.

    Used only to decide whether two strings are the *same* value. The original
    text is always what gets displayed, because "Zoë" is the person's name and
    "zoe" is an implementation detail.

    ``corporate=True`` additionally drops a trailing legal suffix, so the same
    employer arriving as "Acme Ltd" and "Acme" merges instead of appearing as a
    contradiction between two sources who in fact agree.
    """
    folded = unicodedata.normalize("NFKD", str(text))
    folded = "".join(c for c in folded if not unicodedata.combining(c))
    folded = _SPACE.sub(" ", folded).strip().casefold()
    if corporate:
        # Repeated because "Acme Co., Ltd." carries two suffixes.
        previous = None
        while previous != folded:
            previous = folded
            folded = _CORPORATE_SUFFIX.sub("", folded).strip(" ,.")
    return folded


# ---------------------------------------------------------------------------
# one piece of evidence
# ---------------------------------------------------------------------------


@dataclass
class Evidence:
    """One value, as asserted by one or more sources.

    ``sources`` is a list rather than a string because de-duplication *merges*
    corroborating observations into a single record. A value both Wikidata and
    a GitHub profile assert is one row naming both, not two rows that a reader
    has to notice are the same.
    """

    value: str
    source: str
    confidence: float = 0.0
    evidence_type: str = "public_web_profile"
    url: str | None = None
    note: str = ""
    #: Every source that asserted this value, in the order they were added.
    #: Always contains ``source``.
    sources: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.sources:
            self.sources = [self.source] if self.source else []
        if not self.confidence:
            self.confidence = weight_for(self.evidence_type)

    @property
    def corroboration(self) -> int:
        """How many independent sources asserted this value."""
        return len(set(self.sources))

    @property
    def synthetic(self) -> bool:
        """True when this came from a fixture rather than from the world."""
        return self.evidence_type in SYNTHETIC_TYPES

    def to_dict(self) -> dict[str, Any]:
        # The four keys the caller's spec asks for come first and are always
        # present; the rest are additive so a consumer reading only those four
        # keeps working.
        d: dict[str, Any] = {
            "value": self.value,
            "source": self.source,
            "confidence": round(self.confidence, 3),
            "evidence_type": self.evidence_type,
        }
        if len(set(self.sources)) > 1:
            d["sources"] = sorted(set(self.sources))
            d["corroboration"] = self.corroboration
        if self.url:
            d["url"] = self.url
        if self.note:
            d["note"] = self.note
        if self.synthetic:
            d["synthetic"] = True
        return d


# ---------------------------------------------------------------------------
# a field's worth of evidence
# ---------------------------------------------------------------------------


@dataclass
class EvidenceSet:
    """Every value offered for one field, ranked, with the losers kept.

    This is the type that makes the "never silently overwrite" rule structural
    rather than a thing each caller has to remember. There is no API here that
    replaces a value; ``add`` can only ever merge or append.
    """

    #: Compare employer-ish strings with legal suffixes stripped.
    corporate: bool = False
    #: True when this field can legitimately hold several values at once
    #: (aliases, phone numbers). A multi-valued field never reports a conflict,
    #: because a second phone number is ordinary rather than a disagreement.
    multivalued: bool = False
    items: list[Evidence] = field(default_factory=list)

    def add(self, evidence: Evidence) -> Evidence:
        """Merge *evidence* in, and return the record it landed in.

        Merging rather than appending when the normalised values match is what
        turns "three sources said X" into a confidence boost instead of three
        identical rows.
        """
        if not str(evidence.value).strip():
            return evidence
        key = normalise(evidence.value, corporate=self.corporate)
        for existing in self.items:
            if normalise(existing.value, corporate=self.corporate) != key:
                continue
            # Same value, new voice. Record the source, then re-score.
            if evidence.source and evidence.source not in existing.sources:
                existing.sources.append(evidence.source)
            # A stronger kind of source upgrades the record's own type and
            # floor, so a value first seen on a forum and later confirmed by a
            # registry stops being described as forum gossip.
            if weight_for(evidence.evidence_type) > weight_for(existing.evidence_type):
                existing.evidence_type = evidence.evidence_type
                existing.source = evidence.source
            existing.url = existing.url or evidence.url
            existing.note = existing.note or evidence.note
            existing.confidence = self._score(existing)
            return existing

        evidence.confidence = self._score(evidence)
        self.items.append(evidence)
        self._sort()
        return evidence

    def extend(self, items: Iterable[Evidence]) -> None:
        for item in items:
            self.add(item)

    def _score(self, evidence: Evidence) -> float:
        """Base weight, plus a capped bonus for each independent corroboration.

        A synthetic value is pinned to its base weight and never earns the
        bonus: two fixtures agreeing is one fixture written twice.
        """
        base = weight_for(evidence.evidence_type)
        if evidence.synthetic:
            return base
        extra = max(0, evidence.corroboration - 1) * CORROBORATION_STEP
        return min(CORROBORATION_CAP, base + extra)

    def _sort(self) -> None:
        # Confidence first, then corroboration, then the value itself so the
        # ordering is stable across runs and two reports can be diffed.
        self.items.sort(
            key=lambda e: (-e.confidence, -e.corroboration, normalise(e.value)))

    # -- reading -----------------------------------------------------------

    @property
    def best(self) -> Evidence | None:
        """The highest-confidence value, or ``None``.

        Callers that print this **must** also surface :attr:`conflicts`, or
        they have reintroduced the silent overwrite this class exists to stop.
        """
        return self.items[0] if self.items else None

    @property
    def conflicts(self) -> list[Evidence]:
        """Competing values for a single-valued field, best first.

        Empty for a multi-valued field: a person legitimately has two phone
        numbers, and calling that a conflict cries wolf on the flag that is
        supposed to mean somebody is wrong.
        """
        if self.multivalued or len(self.items) < 2:
            return []
        return list(self.items)

    @property
    def disputed(self) -> bool:
        """Different *sources* giving different answers to a single-valued field.

        Two values from the same source is that source being multi-valued about
        something, not a disagreement between sources.
        """
        if self.multivalued or len(self.items) < 2:
            return False
        return len({e.source for e in self.items}) > 1

    def __len__(self) -> int:
        return len(self.items)

    def __iter__(self):
        return iter(self.items)

    def __bool__(self) -> bool:
        return bool(self.items)

    def to_list(self) -> list[dict[str, Any]]:
        """The field as the caller's spec wants it: ranked dicts."""
        return [e.to_dict() for e in self.items]
