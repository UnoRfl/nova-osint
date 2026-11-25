"""Offline tests for the unified contradiction layer.

The layer's job is not to find disagreement - three parts of NOVA already did
that - but to give all of it one shape, and to refuse to turn a disagreement
into an accusation. Most of what is tested here is therefore restraint: that a
multi-valued fact is not a dispute, that a nudge is not a contradiction, and
that every record carries the innocent explanations alongside the clash.
"""

from __future__ import annotations

from nova_osint.core import contradictions as C
from nova_osint.core.brief import Claim, ClaimKind
from nova_osint.core.entities import Entity
from nova_osint.core.entities import EntityType as T
from nova_osint.core.graph import EntityGraph, Observation
from nova_osint.core.identity import Candidate, Check, Resolution, Verdict
from nova_osint.core.models import Confidence, Finding, Investigation, ScanResult, TargetType

NOW = 1_750_000_000.0


def investigation(target="ada", ttype=TargetType.PERSON) -> Investigation:
    return Investigation(target=target, target_type=ttype, started_at=NOW)


def add(inv: Investigation, module: str, *findings: tuple[str, str]) -> ScanResult:
    result = ScanResult(module=module, target=inv.target,
                        target_type=inv.target_type)
    for label, value in findings:
        result.findings.append(Finding(label=label, value=value, source=module,
                                       confidence=Confidence.CONFIRMED))
    inv.results.append(result)
    return result


# ---------------------------------------------------------------------------
# attribute disputes
# ---------------------------------------------------------------------------


def test_two_sources_two_answers_is_a_contradiction():
    inv = investigation()
    add(inv, "wikidata", ("date of birth", "1974-01-01"))
    add(inv, "web", ("date of birth", "1975-06-02"))
    found = [c for c in C.detect(inv) if c.type is C.ContradictionType.ATTRIBUTE]
    assert len(found) == 1
    assert found[0].severity is C.Severity.HIGH
    assert {c.value for c in found[0].claims} == {"1974-01-01", "1975-06-02"}


def test_one_source_with_several_values_is_not_a_dispute():
    """Three degrees from one encyclopaedia is a multi-valued fact."""
    inv = investigation()
    add(inv, "wikidata", ("educated at", "Cambridge"), ("educated at", "MIT"))
    assert [c for c in C.detect(inv)
            if c.type is C.ContradictionType.ATTRIBUTE] == []


def test_severity_follows_how_identifying_the_attribute_is():
    """Nobody has two birthdays; everybody changes jobs."""
    inv = investigation()
    add(inv, "wikidata", ("employer", "Acme"))
    add(inv, "web", ("employer", "Globex"))
    found = [c for c in C.detect(inv) if c.type is C.ContradictionType.ATTRIBUTE]
    assert found[0].severity is C.Severity.LOW


def test_every_contradiction_offers_innocent_explanations():
    inv = investigation()
    add(inv, "wikidata", ("stated location", "Berlin"))
    add(inv, "web", ("stated location", "Lisbon"))
    found = C.detect(inv)[0]
    assert len(found.possible_explanations) >= 4
    assert any("different people" in e for e in found.possible_explanations)
    assert found.resolution_status is C.Resolution.UNRESOLVED


# ---------------------------------------------------------------------------
# ruled-out graph nodes
# ---------------------------------------------------------------------------


def test_a_node_the_evidence_argues_against_becomes_a_contradiction():
    seed = Entity.make(T.USERNAME, "unorfl")
    other = Entity.make(T.USERNAME, "unorfl")
    site = Entity.make(T.URL, "https://example.com/unorfl")
    graph = EntityGraph(seed)
    graph.connect(seed, site, "maybe",
                  Observation(kind="handle-unverified", module="username"))
    graph.connect(seed, site, "denied",
                  Observation(kind="explicit-denial", module="username",
                              detail="the site says this handle is free"))
    graph.rescore()
    inv = investigation(target="unorfl", ttype=TargetType.USERNAME)
    inv.graph = graph
    found = [c for c in C.detect(inv) if c.type is C.ContradictionType.RULED_OUT]
    assert len(found) == 1
    assert found[0].severity is C.Severity.HIGH
    assert found[0].resolution_status is C.Resolution.EVIDENCE_FAVOURS_ONE
    assert any("says this handle is free" in c.value for c in found[0].claims)
    assert other is not None       # entity identity is by value, not object


def test_a_well_supported_node_produces_no_contradiction():
    seed = Entity.make(T.DOMAIN, "a.example")
    other = Entity.make(T.DOMAIN, "b.example")
    graph = EntityGraph(seed)
    graph.connect(seed, other, "cert",
                  Observation(kind="cert-san", module="tls"))
    graph.rescore()
    inv = investigation(target="a.example", ttype=TargetType.DOMAIN)
    inv.graph = graph
    assert [c for c in C.detect(inv)
            if c.type is C.ContradictionType.RULED_OUT] == []


# ---------------------------------------------------------------------------
# candidate claims
# ---------------------------------------------------------------------------


def _resolution(llr: float) -> Resolution:
    candidate = Candidate(label="Ada Lovelace", etype="person")
    candidate.checks.append(Check(
        claim=Claim(kind=ClaimKind.NAME, value="ada lovelace", raw="Ada Lovelace"),
        verdict=Verdict.CONTRADICTS, found="Grace Hopper", llr=llr,
        why="the profile names somebody else", source="wikidata"))
    return Resolution(subject="Ada Lovelace", candidates=[candidate])


def test_a_decisive_mismatch_against_the_brief_is_a_contradiction():
    inv = investigation()
    inv.resolution = _resolution(-4.5)
    found = [c for c in C.detect(inv) if c.type is C.ContradictionType.CLAIM]
    assert len(found) == 1
    assert found[0].severity is C.Severity.HIGH
    assert "the brief you gave" in {c.source for c in found[0].claims}


def test_a_nudge_is_not_promoted_to_a_contradiction():
    """identity scores a mismatched employer at -0.3 on purpose."""
    inv = investigation()
    inv.resolution = _resolution(-0.3)
    assert [c for c in C.detect(inv) if c.type is C.ContradictionType.CLAIM] == []


# ---------------------------------------------------------------------------
# ordering, counting, and not blowing up
# ---------------------------------------------------------------------------


def test_worst_first():
    inv = investigation()
    add(inv, "wikidata", ("employer", "Acme"), ("date of birth", "1974-01-01"))
    add(inv, "web", ("employer", "Globex"), ("date of birth", "1975-06-02"))
    found = C.detect(inv)
    assert [c.severity for c in found] == [C.Severity.HIGH, C.Severity.LOW]


def test_counts_are_by_severity_plus_a_total():
    inv = investigation()
    add(inv, "wikidata", ("date of birth", "1974-01-01"))
    add(inv, "web", ("date of birth", "1975-06-02"))
    counts = C.counts(C.detect(inv))
    assert counts == {"low": 0, "medium": 0, "high": 1, "total": 1}


def test_a_bare_investigation_yields_nothing_rather_than_raising():
    assert C.detect(investigation(ttype=TargetType.DOMAIN)) == []


def test_every_type_has_an_explanation_list():
    """A clash with no innocent reading is an accusation, whatever we call it."""
    for kind in C.ContradictionType:
        assert C.EXPLANATIONS.get(kind), kind


def test_the_record_serialises_whole():
    inv = investigation()
    add(inv, "wikidata", ("date of birth", "1974-01-01"))
    add(inv, "web", ("date of birth", "1975-06-02"))
    d = C.detect(inv)[0].to_dict()
    assert set(d) == {"type", "subject", "summary", "severity", "entities",
                      "claims", "possible_explanations", "resolution_status"}
