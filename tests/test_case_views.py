"""Offline tests for the read-side views over a saved case.

``nova timeline`` / ``contradictions`` / ``pivots`` / ``graph`` all run over a
case rebuilt from the store rather than from a live scan, so the thing most
worth defending is the rebuild: a module that ran and found nothing must not
come back looking like a module that never ran, and a case with no graph must
not make any of the four raise.
"""

from __future__ import annotations

import argparse
import json

import pytest

from nova_osint.commands import (
    cmd_contradictions,
    cmd_graph,
    cmd_pivots,
    cmd_timeline,
    investigation_from_case,
)
from nova_osint.core.entities import Entity
from nova_osint.core.entities import EntityType as T
from nova_osint.core.graph import EntityGraph, Observation
from nova_osint.core.models import (
    Finding,
    Investigation,
    ModuleStatus,
    ScanResult,
    TargetType,
)
from nova_osint.core.store import CaseStore

EXIT_OK, EXIT_NO_FINDINGS, EXIT_USAGE = 0, 1, 2


@pytest.fixture()
def store(tmp_path):
    with CaseStore(tmp_path / "cases") as s:
        yield s


def _args(case, **kw):
    kw.setdefault("format", "text")
    kw.setdefault("limit", 30)
    kw.setdefault("output", None)
    return argparse.Namespace(case=case, **kw)


def _rich_case(store) -> str:
    """One case carrying each thing the four views exist to surface."""
    inv = Investigation(target="unorfl", target_type=TargetType.USERNAME,
                        started_at=1_750_000_000.0)

    github = ScanResult(module="github", target="unorfl",
                        target_type=TargetType.USERNAME)
    github.findings += [
        Finding(label="Account created", value="2025-07-29", source="github"),
        Finding(label="First commit", value="2019-04-02", source="github"),
        Finding(label="stated location", value="Manila", source="github"),
    ]
    wikidata = ScanResult(module="wikidata", target="unorfl",
                          target_type=TargetType.USERNAME)
    wikidata.findings.append(
        Finding(label="stated location", value="Cebu", source="wikidata"))
    quiet = ScanResult(module="keybase", target="unorfl",
                       target_type=TargetType.USERNAME,
                       status=ModuleStatus.EMPTY)
    limited = ScanResult(module="username", target="unorfl",
                         target_type=TargetType.USERNAME,
                         status=ModuleStatus.RATE_LIMITED,
                         status_reason="stopped at 190 of 481")
    inv.results += [github, wikidata, quiet, limited]

    seed = Entity.make(T.USERNAME, "unorfl")
    mail = Entity.make(T.EMAIL, "sales@example.com")
    shop = Entity.make(T.USERNAME, "theshop")
    dead = Entity.make(T.URL, "https://example.test/unorfl")
    graph = EntityGraph(seed)
    graph.connect(seed, mail, "published",
                  Observation(kind="profile-email", module="github"))
    graph.connect(mail, shop, "account",
                  Observation(kind="profile-email", module="web"))
    graph.connect(seed, dead, "denied",
                  Observation(kind="explicit-denial", module="username",
                              detail="the site says this handle is free"))
    graph.rescore()
    inv.graph = graph
    inv.finish().analyse()
    return store.save(inv, graph)


def _bare_case(store) -> str:
    """A case with findings and no graph at all - the oldest shape there is."""
    inv = Investigation(target="example.com", target_type=TargetType.DOMAIN,
                        started_at=1_750_000_000.0)
    res = ScanResult(module="domain", target="example.com",
                     target_type=TargetType.DOMAIN)
    res.findings.append(Finding(label="registrar", value="Example Registrar",
                                source="rdap"))
    inv.results.append(res)
    inv.finish()
    return store.save(inv)


# ---------------------------------------------------------------------------
# rebuilding the investigation
# ---------------------------------------------------------------------------


def test_a_module_that_found_nothing_is_not_lost(store):
    """"Checked, nothing there" and "never checked" are different statements."""
    inv = investigation_from_case(store, _rich_case(store))
    statuses = {r.module: r.status for r in inv.results}
    assert statuses["keybase"] is ModuleStatus.EMPTY
    assert statuses["username"] is ModuleStatus.RATE_LIMITED


def test_the_reason_a_module_fell_short_survives_the_round_trip(store):
    inv = investigation_from_case(store, _rich_case(store))
    limited = next(r for r in inv.results if r.module == "username")
    assert limited.status_reason == "stopped at 190 of 481"
    assert limited in inv.incomplete


def test_the_rebuilt_case_is_analysed(store):
    inv = investigation_from_case(store, _rich_case(store))
    assert inv.analysed
    assert inv.timeline is not None
    assert inv.evidence_summary is not None


def test_an_unknown_case_is_a_usage_error_not_a_crash(store):
    assert investigation_from_case(store, "nope") is None
    assert cmd_timeline(_args("nope"), store) == EXIT_USAGE
    assert cmd_contradictions(_args("nope"), store) == EXIT_USAGE
    assert cmd_pivots(_args("nope"), store) == EXIT_USAGE
    assert cmd_graph(_args("nope", format="graphml"), store) == EXIT_USAGE


# ---------------------------------------------------------------------------
# the views
# ---------------------------------------------------------------------------


def test_timeline_prints_the_chronology(store, capsys):
    assert cmd_timeline(_args(_rich_case(store)), store) == EXIT_OK
    out = capsys.readouterr().out
    assert "2019-04-02" in out and "2025-07-29" in out
    assert "not when NOVA read them" in out


def test_timeline_json_is_machine_readable(store, capsys):
    assert cmd_timeline(_args(_rich_case(store), format="json"), store) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["span"] == ["2019-04-02", "2025-07-29"]
    assert payload["events"]


def test_contradictions_lists_the_innocent_explanations(store, capsys):
    assert cmd_contradictions(_args(_rich_case(store)), store) == EXIT_OK
    out = capsys.readouterr().out
    assert "chronology" in out
    assert "could be:" in out
    assert "not proof that either is false" in out


def test_no_contradictions_says_so_without_claiming_agreement(store, capsys):
    assert cmd_contradictions(_args(_bare_case(store)), store) == EXIT_NO_FINDINGS
    out = capsys.readouterr().out
    assert "not the same as everything agreeing" in out


def test_pivots_rank_by_relevance_and_name_what_was_ruled_out(store, capsys):
    assert cmd_pivots(_args(_rich_case(store)), store) == EXIT_OK
    out = capsys.readouterr().out
    assert "sales@example.com" in out
    assert "ruled out" in out
    assert "https://example.test/unorfl" in out


def test_pivots_never_offers_the_seed_back(store, capsys):
    """Following a pivot to what was just scanned re-runs the scan."""
    cmd_pivots(_args(_rich_case(store)), store)
    listed = [line for line in capsys.readouterr().out.splitlines()
              if line.startswith("  0.") or line.startswith("  1.")]
    assert not any(line.strip().split()[1] == "unorfl" for line in listed)


def test_pivots_json_carries_the_relevance(store, capsys):
    assert cmd_pivots(_args(_rich_case(store), format="json"), store) == EXIT_OK
    rows = json.loads(capsys.readouterr().out)
    assert rows == sorted(rows, key=lambda r: -r["relevance"])
    assert all({"value", "type", "relevance", "reason"} == set(r) for r in rows)


@pytest.mark.parametrize("fmt", ["graph", "graphml", "gexf", "graph-csv", "json"])
def test_graph_exports_in_every_graph_format(store, capsys, fmt):
    assert cmd_graph(_args(_rich_case(store), format=fmt), store) == EXIT_OK
    assert capsys.readouterr().out.strip()


def test_graph_writes_a_file_when_asked(store, tmp_path, capsys):
    out = tmp_path / "nested" / "case.gexf"
    assert cmd_graph(_args(_rich_case(store), format="gexf", output=out),
                     store) == EXIT_OK
    assert "unorfl" in out.read_text("utf-8")


def test_an_unknown_format_is_refused(store):
    assert cmd_graph(_args(_rich_case(store), format="nope"), store) == EXIT_USAGE


# ---------------------------------------------------------------------------
# the oldest case shape must still work
# ---------------------------------------------------------------------------


def test_a_case_with_no_graph_still_answers_every_view(store):
    cid = _bare_case(store)
    assert cmd_timeline(_args(cid), store) == EXIT_NO_FINDINGS
    assert cmd_contradictions(_args(cid), store) == EXIT_NO_FINDINGS
    assert cmd_pivots(_args(cid), store) == EXIT_NO_FINDINGS
    assert cmd_graph(_args(cid, format="graphml"), store) == EXIT_OK
