"""Offline tests for the dossier.

A profile is a document someone will act on, so what is tested here is mostly
what it refuses to do: decide who the subject is, promote a weak finding by
giving it a heading, or let a section quietly vanish because it was empty.
"""

from __future__ import annotations

import json

import pytest

from nova_osint.core.dossier import render_html, render_text
from nova_osint.core.entities import Entity, EntityType
from nova_osint.core.graph import EntityGraph, Observation
from nova_osint.core.models import (
    Investigation,
    ModuleStatus,
    ScanResult,
    Severity,
    TargetType,
)
from nova_osint.core.profile import SECTIONS, build, confidence_line
from nova_osint.core.report import RENDERERS


def _person_investigation():
    """A name search: two candidates, facts hanging off one of them."""
    seed = Entity.make(EntityType.PERSON, "Matthew Prince")
    cand = Entity.make(EntityType.PERSON, "Matthew Prince (Q1)")
    other = Entity.make(EntityType.PERSON, "Matt Prince (Q2)")
    org = Entity.make(EntityType.ORG, "Cloudflare")
    handle = Entity.make(EntityType.USERNAME, "eastdakota")
    weak = Entity.make(EntityType.USERNAME, "the-mrp")

    g = EntityGraph(seed)
    g.connect(seed, cand, "candidate-for", Observation("name-similarity", "wikidata"))
    g.connect(seed, other, "candidate-for", Observation("name-similarity", "wikidata"))
    g.connect(cand, org, "works-at", Observation("wikidata-claim", "wikidata"))
    g.connect(cand, handle, "declared-account", Observation("wikidata-claim", "wikidata"))
    g.connect(seed, handle, "handle-stem", Observation("handle-derived", "bluesky"))
    g.connect(seed, weak, "handle-stem", Observation("handle-derived", "bluesky"))
    g.rescore()

    inv = Investigation(target="Matthew Prince", target_type=TargetType.PERSON)
    res = ScanResult(module="wikidata", target="Matthew Prince",
                     target_type=TargetType.PERSON)
    res.add("ambiguity", "2 entities share this name", source="wikidata")
    res.add("account created", "2011-09-03", source="wikidata")
    res.add("public email", "m@example.com", source="wikidata", severity=Severity.HIGH)
    inv.results.append(res)
    blocked = ScanResult(module="github", target="Matthew Prince",
                         target_type=TargetType.PERSON)
    blocked.status = ModuleStatus.BLOCKED
    blocked.status_reason = "rate limited"
    inv.results.append(blocked)
    inv.skipped.append(("virustotal", "needs $VT_API_KEY"))
    inv.graph = g
    return inv.finish()


# ---------------------------------------------------------------------------
# who the subject is
# ---------------------------------------------------------------------------


def test_facts_attach_to_the_candidate_not_to_the_shared_name():
    """The central guarantee. Caught live before it was a test."""
    profile = build(_person_investigation())
    direct = {r.b for r in profile.relationships if not r.indirect}
    assert "Cloudflare" not in direct, "employer must not hang off the bare name"
    indirect = {(r.a, r.relation, r.b) for r in profile.relationships if r.indirect}
    assert ("Matthew Prince (Q1)", "works-at", "Cloudflare") in indirect


def test_both_candidates_survive_as_separate_people():
    profile = build(_person_investigation())
    names = {c.value for c in profile.candidates}
    assert names == {"Matthew Prince (Q1)", "Matt Prince (Q2)"}


def test_the_ambiguity_warning_comes_before_any_fact():
    """A dossier that opens with an employer has claimed an identification."""
    text = render_text(build(_person_investigation()))
    assert text.index("WHO THIS IS") < text.index("Cloudflare")
    assert "has not decided which of these is your subject" in text


def test_a_confident_subject_gets_no_candidate_section():
    inv = Investigation(target="example.com", target_type=TargetType.DOMAIN)
    seed = Entity.make(EntityType.DOMAIN, "example.com")
    g = EntityGraph(seed)
    g.connect(seed, Entity.make(EntityType.IP, "203.0.113.1"), "resolves-to",
              Observation("dns-a", "dns"))
    g.rescore()
    inv.graph = g
    profile = build(inv.finish())
    assert profile.candidates == []
    assert "WHO THIS IS" not in render_text(profile)


# ---------------------------------------------------------------------------
# relevance vs corroboration
# ---------------------------------------------------------------------------


def test_relevance_and_corroboration_are_separate_numbers():
    """They answer different questions and conflating them misranks a list."""
    profile = build(_person_investigation())
    accounts = profile.sections["Accounts"]
    best = accounts[0]
    assert best.value == "eastdakota"
    assert best.corroboration == 2, "wikidata and bluesky both saw it"
    assert best.llr > accounts[1].llr


def test_a_well_evidenced_but_loosely_connected_entity_still_ranks_first():
    profile = build(_person_investigation())
    names = [a.value for a in profile.sections["Accounts"]]
    assert names[0] == "eastdakota"


def test_the_text_dossier_shows_both_numbers():
    text = render_text(build(_person_investigation()))
    assert "rel " in text and "2 sources" in text


# ---------------------------------------------------------------------------
# honesty about what is missing
# ---------------------------------------------------------------------------


def test_empty_sections_are_printed_not_dropped():
    """A missing heading reads as 'nothing there', which is a different claim."""
    text = render_text(build(_person_investigation()))
    for heading, _kinds, _note in SECTIONS:
        assert heading.upper() in text
    assert "(none found)" in text


def test_coverage_gaps_travel_with_the_profile():
    profile = build(_person_investigation())
    assert any("github" in g for g in profile.gaps)
    assert any("virustotal" in g for g in profile.gaps)
    text = render_text(profile)
    assert "COVERAGE GAPS" in text
    assert "not evidence of absence" in text


def test_a_truncated_scan_says_so_in_the_dossier():
    from nova_osint.core.engine import Expansion

    inv = _person_investigation()
    inv.expansion = Expansion(stopped_by="entity cap (8)")
    profile = build(inv)
    assert profile.truncated == "entity cap (8)"
    assert "incomplete" in render_text(profile)


def test_a_complete_scan_does_not_claim_to_be_truncated():
    from nova_osint.core.engine import Expansion

    inv = _person_investigation()
    inv.expansion = Expansion(stopped_by="frontier exhausted")
    assert build(inv).truncated == ""


def test_the_assessment_line_counts_weak_evidence_honestly():
    profile = build(_person_investigation())
    line = confidence_line(profile)
    assert "on weak or none" in line
    assert "leads, not facts" in line


# ---------------------------------------------------------------------------
# timeline and exposure
# ---------------------------------------------------------------------------


def test_dated_findings_become_a_timeline():
    profile = build(_person_investigation())
    assert profile.timeline and profile.timeline[0][0] == "2011-09-03"


def test_the_timeline_does_not_repeat_a_date_two_modules_both_reported():
    inv = _person_investigation()
    extra = ScanResult(module="other", target="x", target_type=TargetType.PERSON)
    extra.add("account created", "2011-09-03", source="other")
    inv.results.append(extra)
    profile = build(inv)
    stamps = [(w, what) for w, what, _ in profile.timeline]
    assert len(stamps) == len(set(stamps))


def test_high_interest_findings_are_lifted_into_exposure():
    profile = build(_person_investigation())
    assert any("public email" in label for label, _v, _m in profile.exposure)


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def test_html_escapes_a_hostile_subject():
    inv = _person_investigation()
    inv.target = "<script>alert(1)</script>"
    page = render_html(build(inv))
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_the_renderers_are_registered_and_produce_output():
    inv = _person_investigation()
    assert RENDERERS["profile"](inv).startswith("=")
    assert RENDERERS["profile-html"](inv).startswith("<!doctype html>")
    payload = json.loads(RENDERERS["profile-json"](inv))
    assert payload["subject"] == "Matthew Prince"
    assert payload["summary"]["relationships"] == len(build(inv).relationships)
    assert payload["coverage_gaps"]


def test_a_graphless_investigation_still_renders():
    inv = Investigation(target="x.test", target_type=TargetType.DOMAIN).finish()
    profile = build(inv)
    assert profile.entities == 0
    assert "COVERAGE GAPS" in render_text(profile)
    assert render_html(profile).startswith("<!doctype html>")


@pytest.mark.parametrize("fmt", ["profile", "profile-html", "profile-json"])
def test_every_profile_format_carries_the_ambiguity_warning(fmt):
    out = RENDERERS[fmt](_person_investigation())
    assert "2 entities share this name" in out
