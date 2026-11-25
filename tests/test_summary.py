"""Offline tests for the evidence summary and the four information classes.

The summary exists because ``281 findings`` is a number that rises when a scan
touches more sites, which is the one property a quality measure must not have.
These tests hold the replacement to the same standard: every field has to be
countable from the investigation, and the counting has to survive an
investigation that has no graph at all.
"""

from __future__ import annotations

from nova_osint.core import summary as S
from nova_osint.core.acquisition import Acquisition, Method
from nova_osint.core.entities import Entity
from nova_osint.core.entities import EntityType as T
from nova_osint.core.graph import EVIDENCE, EntityGraph, Observation
from nova_osint.core.models import (
    Confidence,
    Finding,
    Investigation,
    ModuleStatus,
    ScanResult,
    TargetType,
)

NOW = 1_750_000_000.0


def investigation() -> Investigation:
    return Investigation(target="unorfl", target_type=TargetType.USERNAME,
                         started_at=NOW)


def add(inv, module, *findings, status=ModuleStatus.SUCCESS):
    result = ScanResult(module=module, target=inv.target,
                        target_type=inv.target_type, status=status)
    for finding in findings:
        result.findings.append(finding)
    inv.results.append(result)
    return result


# ---------------------------------------------------------------------------
# the four classes
# ---------------------------------------------------------------------------


def test_every_evidence_kind_is_classified():
    """A kind nobody classified falls back to the class readers trust least.

    That fallback is deliberate, but it must never be reached by accident: the
    cost of a new evidence kind is one line in ``CLASS_BY_KIND``.
    """
    missing = sorted(set(EVIDENCE) - set(S.CLASS_BY_KIND))
    assert missing == [], f"unclassified evidence kinds: {missing}"


def test_no_classification_for_a_kind_that_does_not_exist():
    """The table drifting the other way is just as bad."""
    extra = sorted(set(S.CLASS_BY_KIND) - set(EVIDENCE))
    assert extra == [], f"classified kinds with no entry in EVIDENCE: {extra}"


def test_strength_and_class_are_independent():
    """spki-shared is inferred *and* worth six nats. Both, not either."""
    assert S.classify_kind("spki-shared") is S.EvidenceClass.INFERRED
    assert EVIDENCE["spki-shared"] >= 6.0


def test_a_locally_computed_finding_is_derived():
    finding = Finding(label="Local part", value="improvised30", source="email",
                      acquisition=Acquisition(method=Method.LOCAL,
                                              provider="email"))
    assert S.classify_finding(finding) is S.EvidenceClass.DERIVED


def test_a_search_result_is_a_lead_not_an_observation():
    finding = Finding(label="Mentioned", value="somewhere", source="websearch",
                      acquisition=Acquisition(method=Method.SEARCH,
                                              provider="marginalia"))
    assert S.classify_finding(finding) is S.EvidenceClass.UNVERIFIED


def test_a_weak_finding_is_unverified_even_without_an_acquisition():
    finding = Finding(label="Possible real name", value="R R", source="email",
                      confidence=Confidence.POSSIBLE)
    assert S.classify_finding(finding) is S.EvidenceClass.UNVERIFIED


def test_an_ordinary_api_finding_is_observed():
    finding = Finding(label="Account created", value="2025-07-29",
                      source="github",
                      acquisition=Acquisition(method=Method.API,
                                              provider="github"))
    assert S.classify_finding(finding) is S.EvidenceClass.OBSERVED


# ---------------------------------------------------------------------------
# counting
# ---------------------------------------------------------------------------


def test_independent_sources_counts_sources_not_observations():
    """Three kinds off one fetch by one module is one source's word."""
    a, b = Entity.make(T.DOMAIN, "a.example"), Entity.make(T.DOMAIN, "b.example")
    graph = EntityGraph(a)
    for kind in ("tracker-id-shared", "favicon-hash", "page-structure-hash"):
        graph.connect(a, b, "same site",
                      Observation(kind=kind, module="web",
                                  url="https://a.example/"))
    graph.rescore()
    inv = investigation()
    inv.graph = graph
    built = S.build(inv, contradictions=[])
    assert built.observations == 3
    assert built.independent_sources == 1


def test_relationships_split_at_the_admiralty_b_boundary():
    a = Entity.make(T.DOMAIN, "a.example")
    strong = Entity.make(T.DOMAIN, "strong.example")
    weak = Entity.make(T.DOMAIN, "weak.example")
    graph = EntityGraph(a)
    graph.connect(a, strong, "cert", Observation(kind="cert-san", module="tls"))
    graph.connect(a, weak, "seen", Observation(kind="mentioned", module="web"))
    graph.rescore()
    inv = investigation()
    inv.graph = graph
    built = S.build(inv, contradictions=[])
    assert built.strong_relationships == 1
    assert built.candidate_relationships == 1
    assert built.negative_relationships == 0


def test_an_edge_argued_against_is_counted_separately():
    a, b = Entity.make(T.USERNAME, "unorfl"), Entity.make(T.URL, "https://x.test/u")
    graph = EntityGraph(a)
    graph.connect(a, b, "denied",
                  Observation(kind="explicit-denial", module="username"))
    graph.rescore()
    inv = investigation()
    inv.graph = graph
    assert S.build(inv, contradictions=[]).negative_relationships == 1


def test_module_statuses_are_tallied_including_the_ones_that_never_ran():
    inv = investigation()
    add(inv, "github", Finding(label="x", value="y", source="github"))
    add(inv, "username", status=ModuleStatus.RATE_LIMITED)
    inv.skipped.append(("virustotal", "no API key"))
    built = S.build(inv, contradictions=[])
    assert built.modules_total == 3
    assert built.modules["rate limited"] == 1
    assert built.modules["skipped"] == 1


def test_declined_leads_are_reported_by_the_rule_that_stopped_them():
    inv = investigation()
    inv.not_followed.append(("action@github.com", "automated address"))
    inv.not_followed.append(("noreply@github.com", "automated address"))
    built = S.build(inv, contradictions=[])
    assert built.declined == {"automated address": 2}


def test_a_graphless_investigation_still_counts_sources():
    """Zero would read as "no sources", which is a different statement."""
    inv = investigation()
    add(inv, "github", Finding(label="x", value="y", source="github"))
    add(inv, "email", Finding(label="a", value="b", source="email"))
    built = S.build(inv, contradictions=[])
    assert built.independent_sources == 2
    assert built.entities == 0


def test_the_summary_serialises_and_reads_as_lines():
    inv = investigation()
    add(inv, "github", Finding(label="x", value="y", source="github"))
    built = S.build(inv)
    assert built.to_dict()["modules"]["total"] == 1
    assert any("Independent sources" in line for line in built.lines())


def test_a_bare_investigation_summarises_to_zeroes_rather_than_raising():
    built = S.build(investigation())
    assert built.findings == 0
    assert built.contradictions["total"] == 0


def test_the_class_breakdown_sums_to_the_stated_total():
    """A block of numbers under a heading naming a smaller total is unreadable.

    ``by_class`` covers findings *and* graph observations; the summary used to
    print it directly under "Observations on the graph: 6" while the four
    numbers added to 13.
    """
    a, b = Entity.make(T.DOMAIN, "a.example"), Entity.make(T.DOMAIN, "b.example")
    graph = EntityGraph(a)
    graph.connect(a, b, "cert", Observation(kind="cert-san", module="tls"))
    graph.rescore()
    inv = investigation()
    add(inv, "github", Finding(label="x", value="y", source="github"))
    inv.graph = graph

    built = S.build(inv, contradictions=[])
    assert built.claims == built.findings + built.observations
    assert sum(built.by_class.values()) == built.claims
    assert f"({built.claims} in total)" in "\n".join(built.lines())
