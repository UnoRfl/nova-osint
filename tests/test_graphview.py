"""Offline tests for the graph renderers and redaction.

The page is checked structurally rather than visually: that it is
self-contained, that every node and edge reaches the payload, and that the
evidence behind an edge survives into the document. A picture that quietly drops
the weakest or strongest links would be worse than no picture.
"""

from __future__ import annotations

import json
import re

import pytest

from nova_osint.core.entities import Entity, EntityType
from nova_osint.core.graph import EntityGraph, Observation
from nova_osint.core.graphview import (
    PERSONAL,
    Redactor,
    graph_payload,
    probability_note,
    redact_investigation,
    render_graph_html,
    render_graphml,
)
from nova_osint.core.models import Investigation, ScanResult, TargetType
from nova_osint.core.report import RENDERERS


def _investigation():
    seed = Entity.make(EntityType.DOMAIN, "example.com")
    email = Entity.make(EntityType.EMAIL, "alice@example.com")
    handle = Entity.make(EntityType.USERNAME, "alice")
    ip = Entity.make(EntityType.IP, "203.0.113.10")
    graph = EntityGraph(seed)
    graph.connect(seed, email, "contact", Observation(
        "rdap-contact", "whois", url="https://rdap.test/x", evidence="a" * 64))
    graph.connect(email, handle, "same-as", Observation("commit-email", "github"))
    graph.connect(seed, ip, "resolves-to", Observation("dns-a", "dns"))
    graph.rescore()

    inv = Investigation(target="example.com", target_type=TargetType.DOMAIN)
    res = ScanResult(module="whois", target="example.com",
                     target_type=TargetType.DOMAIN)
    res.add("registrant email", "alice@example.com", source="rdap")
    res.add("phone", "+44 20 7946 0958", source="rdap")
    res.add("nameservers", ["ns1.example.com", "ns2.example.com"], source="dns")
    inv.results.append(res)
    inv.graph = graph
    return inv.finish()


# ---------------------------------------------------------------------------
# payload
# ---------------------------------------------------------------------------


def test_every_node_and_edge_reaches_the_payload():
    inv = _investigation()
    data = graph_payload(inv)
    assert len(data["nodes"]) == len(inv.graph)
    assert len(data["edges"]) == len(inv.graph.edges)
    assert data["seed"] == "domain:example.com"


def test_payload_carries_the_evidence_behind_each_edge():
    data = graph_payload(_investigation())
    edge = next(e for e in data["edges"] if e["label"] == "contact")
    why = edge["why"][0]
    assert why["kind"] == "rdap-contact" and why["module"] == "whois"
    assert why["url"] == "https://rdap.test/x"
    assert why["evidence"] == "a" * 64
    assert edge["grade"] and 0 < edge["probability"] < 1


def test_payload_marks_the_seed_and_keeps_scores():
    data = graph_payload(_investigation())
    seed = next(n for n in data["nodes"] if n["seed"])
    assert seed["id"] == "domain:example.com" and seed["score"] == 1.0
    assert all(0 <= n["score"] <= 1 for n in data["nodes"])


def test_a_graphless_investigation_renders_empty_rather_than_raising():
    inv = Investigation(target="x.test", target_type=TargetType.DOMAIN).finish()
    assert graph_payload(inv)["nodes"] == []
    assert "<canvas" in render_graph_html(inv)


# ---------------------------------------------------------------------------
# the page
# ---------------------------------------------------------------------------


def test_the_page_is_self_contained():
    """No CDN. A report that needs the internet is not a case file."""
    page = render_graph_html(_investigation())
    assert "<script" in page
    assert not re.search(r"<script[^>]+src=", page), "external script tag"
    assert not re.search(r"<link[^>]+href=['\"]https?://", page), "external stylesheet"
    for host in ("cdn.", "unpkg", "jsdelivr", "googleapis", "d3js.org"):
        assert host not in page


def test_the_page_embeds_its_own_data():
    page = render_graph_html(_investigation())
    payload = json.loads(re.search(r"const DATA = (\{.*?\}), COLORS", page,
                                   re.S).group(1))
    assert len(payload["nodes"]) == 4
    assert payload["target"] == "example.com"


def test_the_page_reports_what_the_expansion_did_not_reach():
    from nova_osint.core.engine import Expansion

    inv = _investigation()
    inv.expansion = Expansion(rounds=2, module_runs=6, expanded=["domain:example.com"],
                              stopped_by="entity cap (40)",
                              unexplored=[("username:alice", 0.31)])
    page = render_graph_html(inv)
    assert "entity cap (40)" in page
    assert "username:alice" in page
    assert "Leads not reached" in page


def test_html_escaping_of_a_hostile_target():
    inv = _investigation()
    inv.target = "<script>alert(1)</script>.test"
    page = render_graph_html(inv)
    assert "<script>alert(1)</script>.test" not in page
    assert "&lt;script&gt;" in page


# ---------------------------------------------------------------------------
# GraphML
# ---------------------------------------------------------------------------


def test_graphml_is_well_formed_and_complete():
    import xml.etree.ElementTree as ET

    inv = _investigation()
    root = ET.fromstring(render_graphml(inv))
    ns = "{http://graphml.graphdrawing.org/xmlns}"
    graph = root.find(f"{ns}graph")
    assert len(graph.findall(f"{ns}node")) == len(inv.graph)
    assert len(graph.findall(f"{ns}edge")) == len(inv.graph.edges)


def test_graphml_keeps_the_reason_for_each_edge():
    out = render_graphml(_investigation())
    assert "rdap-contact (whois)" in out
    assert "commit-email (github)" in out


def test_graphml_escapes_markup_in_values():
    inv = _investigation()
    bad = Entity.make(EntityType.PERSON, "A <b>name</b>")
    inv.graph.connect(inv.graph.nodes[inv.graph.seed].entity, bad, "named",
                      Observation("rdap-contact", "whois"))
    out = render_graphml(inv)
    assert "<b>name</b>" not in out and "&lt;b&gt;" in out


# ---------------------------------------------------------------------------
# redaction
# ---------------------------------------------------------------------------


def test_redaction_is_consistent_within_a_report():
    """Two accounts sharing an address must still visibly share it."""
    red = Redactor(True)
    a = red.entity(EntityType.EMAIL, "alice@example.com")
    b = red.entity(EntityType.EMAIL, "alice@example.com")
    c = red.entity(EntityType.EMAIL, "bob@example.com")
    assert a == b and a != c
    assert "alice" not in a and a.startswith("email:")


def test_redaction_leaves_infrastructure_alone():
    red = Redactor(True)
    for kind in (EntityType.DOMAIN, EntityType.IP, EntityType.ASN, EntityType.HOST):
        assert kind not in PERSONAL
        assert red.entity(kind, "example.com") == "example.com"


def test_redaction_salt_changes_the_tokens():
    a = Redactor(True, "one").entity(EntityType.EMAIL, "alice@example.com")
    b = Redactor(True, "two").entity(EntityType.EMAIL, "alice@example.com")
    c = Redactor(True, "one").entity(EntityType.EMAIL, "alice@example.com")
    assert a != b and a == c


def test_redaction_masks_addresses_inside_free_text():
    red = Redactor(True)
    out = red.text("contact abuse@example.com or call +44 20 7946 0958")
    assert "abuse@example.com" not in out
    assert "7946" not in out
    assert "email:" in out and "phone:" in out


def test_disabled_redactor_is_a_no_op():
    red = Redactor(False)
    assert red.text("alice@example.com") == "alice@example.com"
    assert red.entity(EntityType.EMAIL, "alice@example.com") == "alice@example.com"


def test_redacting_an_investigation_does_not_touch_the_original():
    """The store keeps the real values; only the rendering is masked."""
    inv = _investigation()
    red = Redactor(True)
    masked = redact_investigation(inv, red)

    assert inv.findings[0].value == "alice@example.com", "original was mutated"
    assert "alice@example.com" not in str(masked.findings[0].value)
    assert "email:" in str(masked.findings[0].value)
    # ...and the graph node is masked too, or the picture would leak it back.
    assert not any("alice@example.com" in n.entity.value for n in masked.graph)
    assert any("alice@example.com" in n.entity.value for n in inv.graph)


def test_redacting_a_list_valued_finding():
    inv = _investigation()
    masked = redact_investigation(inv, Redactor(True))
    ns = next(f for f in masked.findings if f.label == "nameservers")
    assert ns.value == ["ns1.example.com", "ns2.example.com"], "hosts are not personal"


def test_a_redacted_page_says_it_is_redacted():
    inv = _investigation()
    red = Redactor(True)
    masked = redact_investigation(inv, red)
    page = render_graph_html(masked, red)
    assert "redacted" in page
    assert "alice@example.com" not in page


# ---------------------------------------------------------------------------
# wiring
# ---------------------------------------------------------------------------


def test_the_new_formats_are_registered():
    assert "graph" in RENDERERS and "graphml" in RENDERERS
    inv = _investigation()
    assert RENDERERS["graph"](inv).startswith("<!doctype html>")
    assert RENDERERS["graphml"](inv).startswith("<?xml")


def test_every_renderer_survives_an_investigation_with_a_graph():
    inv = _investigation()
    for name, render in RENDERERS.items():
        out = render(inv)
        assert isinstance(out, str) and out.strip(), name


@pytest.mark.parametrize("llr,expected", [
    (8.0, "near certain"), (2.5, "probable"), (0.6, "more likely than not"),
    (0.05, "weakly suggestive"), (-2.0, "no support"),
])
def test_probability_note_reads_as_english(llr, expected):
    assert expected in probability_note(llr)


# ---------------------------------------------------------------------------
# graded connections in the text reports
# ---------------------------------------------------------------------------


def test_connection_rows_are_ordered_by_evidence_strength():
    from nova_osint.core.report import connection_rows

    rows = connection_rows(_investigation())
    grades = [r[0] for r in rows]
    assert grades == sorted(grades), "strongest evidence must come first"
    assert rows[0][0].startswith("B")


def test_connection_rows_name_the_evidence_and_read_it_in_english():
    """A log-odds figure is precise and meaningless to most readers."""
    from nova_osint.core.report import connection_rows

    rows = {r[1]: r for r in connection_rows(_investigation())}
    grade, label, relation, why, reading = rows["alice@example.com"]
    assert relation == "contact" and why == "rdap-contact"
    assert reading in ("near certain", "probable", "more likely than not",
                       "weakly suggestive", "no support, or evidence against")


def test_a_graphless_investigation_has_no_connection_rows():
    from nova_osint.core.report import connection_rows

    inv = Investigation(target="x.test", target_type=TargetType.DOMAIN).finish()
    assert connection_rows(inv) == []


@pytest.mark.parametrize("fmt", ["console", "markdown", "html"])
def test_every_text_report_shows_how_the_pieces_connect(fmt):
    out = RENDERERS[fmt](_investigation())
    assert "connect" in out.lower(), f"{fmt} hides the link analysis"
    assert "alice@example.com" in out


@pytest.mark.parametrize("fmt", ["console", "markdown", "html"])
def test_every_text_report_explains_the_admiralty_grade(fmt):
    """A grade nobody can read is decoration."""
    out = RENDERERS[fmt](_investigation())
    assert "Admiralty" in out or "admiralty" in out
    assert "corroboration" in out
