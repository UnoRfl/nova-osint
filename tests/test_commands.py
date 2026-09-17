"""Offline tests for the case commands, the replay engine and doctor's verdicts.

No network. ``doctor`` is tested at the level that matters - how it *classifies*
a response - because the classification is the whole point: "refused us" and
"needs a key" and "unreachable" all produce an empty report section and mean
three different things.
"""

from __future__ import annotations

import argparse
import json

import pytest

from nova_osint.commands import (
    _verdict,
    cmd_diff,
    cmd_evidence,
    cmd_history,
    cmd_link,
    cmd_replay,
    cmd_show,
    cmd_where,
)
from nova_osint.core import registry
from nova_osint.core.config import Config
from nova_osint.core.entities import Entity, EntityType
from nova_osint.core.graph import EntityGraph, Observation
from nova_osint.core.http import Response
from nova_osint.core.models import Investigation, ModuleStatus, ScanResult, TargetType
from nova_osint.core.registry import Module
from nova_osint.core.replay import MISSING, ReplayFetcher, replay
from nova_osint.core.store import CaseStore


@pytest.fixture()
def store(tmp_path):
    with CaseStore(tmp_path / "cases") as s:
        yield s


def _args(**kw):
    kw.setdefault("format", "text")
    kw.setdefault("limit", 20)
    return argparse.Namespace(**kw)


def _case(store, target="example.com", *, mx="a.mx.test", case_id=None,
          status=ModuleStatus.SUCCESS, requests=None, module="fake-dns"):
    inv = Investigation(target=target, target_type=TargetType.DOMAIN)
    res = ScanResult(module=module, target=target, target_type=TargetType.DOMAIN)
    seed = Entity.make(EntityType.DOMAIN, target)
    res.subject = seed
    res.add("MX", mx, source="doh")
    res.entity(EntityType.IP, "203.0.113.10", relation="resolves-to", evidence="dns-a")
    res.status = status
    inv.results.append(res)
    inv.finish()
    graph = EntityGraph(seed)
    for link in res.links:
        graph.connect(link.src, link.dst, link.label,
                      Observation(link.kind, link.module))
    graph.rescore()
    return store.save(inv, graph, case_id=case_id, requests=requests or [])


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status,key,have_key,expected", [
    (200, None, False, "ok"),
    (404, None, False, "ok"),        # reachable is the question, not found
    (429, None, False, "limited"),
    (403, None, False, "blocked"),
    (503, None, False, "down"),
    (401, "github", False, "key"),   # working correctly, we just have no key
    (403, "github", False, "key"),
    (403, "github", True, "blocked"),  # we had a key and were still refused
])
def test_doctor_verdicts(status, key, have_key, expected):
    verdict, note = _verdict(Response(url="u", status=status), key, have_key)
    assert verdict == expected and note


def test_doctor_reports_a_dead_host_as_down_not_as_empty():
    verdict, note = _verdict(
        Response(url="u", status=0, error="Connection refused"), None, False)
    assert verdict == "down" and "refused" in note.lower()


def test_every_probe_is_well_formed():
    from nova_osint.commands import PROBES
    from nova_osint.core.config import KEY_INFO

    names = [p.source for p in PROBES]
    assert len(names) == len(set(names)), "duplicate probe name"
    for probe in PROBES:
        assert probe.url.startswith(("http://", "https://")), probe.source
        assert probe.provides and not probe.provides.endswith("."), probe.source
        assert probe.timeout > 0
        if probe.key is not None:
            assert probe.key in KEY_INFO, (
                f"{probe.source} probes for an unknown key {probe.key!r}")


def test_doh_probes_send_the_header_the_resolver_requires():
    """DoH answers 400 to a bare GET.

    The first version of doctor did exactly that and reported a healthy
    Cloudflare as unreachable - a checker that calls a working source broken is
    one people learn to ignore.
    """
    from nova_osint.commands import PROBES

    doh = [p for p in PROBES if "dns-query" in p.url or "/resolve?" in p.url]
    assert doh, "no DoH probes left to check"
    for probe in doh:
        assert probe.headers.get("accept") == "application/dns-json", probe.source


def test_slow_sources_get_the_timeout_their_module_allows():
    """A probe stricter than the scan reports a gap the scan will not hit."""
    from nova_osint.commands import PROBES

    crtsh = next(p for p in PROBES if p.source == "crt.sh")
    assert crtsh.timeout >= 45.0


# ---------------------------------------------------------------------------
# history / show / where
# ---------------------------------------------------------------------------


def test_history_says_the_store_is_empty_rather_than_printing_nothing(store, capsys):
    assert cmd_history(_args(target=None), store) == 1
    assert "no saved cases" in capsys.readouterr().err


def test_history_lists_cases(store, capsys):
    _case(store, "a.test")
    _case(store, "b.test")
    assert cmd_history(_args(target=None), store) == 0
    out = capsys.readouterr().out
    assert "a.test" in out and "b.test" in out


def test_history_json_is_machine_readable(store, capsys):
    _case(store, "a.test")
    cmd_history(_args(target=None, format="json"), store)
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["target"] == "a.test" and rows[0]["summary"]["findings"] == 1


def test_show_prints_findings_and_the_path_to_each_entity(store, capsys):
    cid = _case(store)
    assert cmd_show(_args(case=cid), store) == 0
    out = capsys.readouterr().out
    assert "MX: a.mx.test" in out
    assert "ip:203.0.113.10" in out
    assert "domain:example.com -> ip:203.0.113.10" in out


def test_show_calls_out_coverage_gaps(store, capsys):
    cid = _case(store, status=ModuleStatus.BLOCKED)
    cmd_show(_args(case=cid), store)
    assert "coverage gap" in capsys.readouterr().out


def test_show_rejects_an_unknown_case(store, capsys):
    assert cmd_show(_args(case="nope"), store) == 2
    assert "no such case" in capsys.readouterr().err


def test_where_finds_the_cases_that_saw_a_value(store, capsys):
    _case(store, "a.test", case_id="a")
    _case(store, "b.test", case_id="b")
    assert cmd_where(_args(value="203.0.113.10", type="ip"), store) == 0
    out = capsys.readouterr().out
    assert "a" in out and "b" in out


def test_where_reports_nothing_found(store, capsys):
    _case(store)
    assert cmd_where(_args(value="198.51.100.99", type="ip"), store) == 1


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------


def test_diff_between_the_last_two_runs_of_one_target(store, capsys):
    _case(store, mx="old.mx.test", case_id="20260101-000000-aaaaaa")
    _case(store, mx="new.mx.test", case_id="20260102-000000-aaaaaa")
    assert cmd_diff(_args(old="example.com", new=None), store) == 0
    out = capsys.readouterr().out
    assert "was: old.mx.test" in out and "now: new.mx.test" in out


def test_diff_needs_two_runs(store, capsys):
    _case(store)
    assert cmd_diff(_args(old="example.com", new=None), store) == 2
    assert "need two saved cases" in capsys.readouterr().err


def test_diff_of_identical_runs_says_no_change(store, capsys):
    _case(store, case_id="20260101-000000-aaaaaa")
    _case(store, case_id="20260102-000000-aaaaaa")
    assert cmd_diff(_args(old="example.com", new=None), store) == 1
    assert "no change" in capsys.readouterr().out


def test_diff_puts_coverage_changes_before_the_findings_they_explain(store, capsys):
    """A module going dark reframes every removal under it.

    A reader who meets the removals first has already concluded the data
    disappeared by the time they reach the explanation.
    """
    _case(store, case_id="old", status=ModuleStatus.SUCCESS)
    _case(store, case_id="new", mx="changed.mx.test", status=ModuleStatus.BLOCKED)
    cmd_diff(_args(old="old", new="new"), store)
    out = capsys.readouterr().out
    assert out.index("coverage") < out.index("MX")


# ---------------------------------------------------------------------------
# link
# ---------------------------------------------------------------------------


def test_link_separates_a_real_connection_from_shared_infrastructure(store, capsys):
    shared = Entity.make(EntityType.EMAIL, "admin@example.com")
    cdn = Entity.make(EntityType.IP, "198.51.100.1")
    ids = []
    for name in ("a.test", "b.test"):
        seed = Entity.make(EntityType.DOMAIN, name)
        g = EntityGraph(seed)
        g.connect(seed, shared, "contact", Observation("rdap-contact", "whois"))
        g.connect(seed, cdn, "resolves-to", Observation("dns-a", "dns"))
        for i in range(20):
            g.connect(cdn, Entity.make(EntityType.DOMAIN, f"t{i}.test"), "hosts",
                      Observation("shared-hosting", "dns"))
        g.rescore()
        inv = Investigation(target=name, target_type=TargetType.DOMAIN).finish()
        ids.append(store.save(inv, g, case_id=name))

    assert cmd_link(_args(case_a=ids[0], case_b=ids[1]), store) == 0
    out = capsys.readouterr().out
    real, infra = out.split("shared infrastructure")
    assert "admin@example.com" in real
    assert "198.51.100.1" in infra
    assert "not evidence of a link" in out


def test_link_with_nothing_in_common(store, capsys):
    a = _case(store, "a.test", case_id="a")
    inv = Investigation(target="b.test", target_type=TargetType.DOMAIN).finish()
    b = store.save(inv, EntityGraph(Entity.make(EntityType.DOMAIN, "b.test")),
                   case_id="b")
    assert cmd_link(_args(case_a=a, case_b=b), store) == 1
    assert "nothing in common" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------


class Recorded(Module):
    """A module whose findings come from one fetched document."""

    name = "fake-recorded"
    accepts = frozenset({TargetType.DOMAIN})
    fields = ("alpha", "beta")

    def run(self, target: str, result: ScanResult) -> None:
        data = self.http.get_json(f"https://src.test/{target}") or {}
        for field in self.fields:
            if field in data:
                result.add(field, data[field], source="fake")


@pytest.fixture()
def recorded_case(store):
    saved, flag = dict(registry._REGISTRY), registry._imported
    registry._REGISTRY.clear()
    registry._REGISTRY["fake-recorded"] = Recorded
    registry._imported = True

    body = json.dumps({"alpha": 1, "beta": 2}).encode()
    digest = store.evidence.put(body)
    inv = Investigation(target="example.com", target_type=TargetType.DOMAIN)
    res = ScanResult(module="fake-recorded", target="example.com",
                     target_type=TargetType.DOMAIN)
    res.add("alpha", 1, source="fake")
    res.add("beta", 2, source="fake")
    inv.results.append(res)
    inv.finish()
    cid = store.save(inv, None, case_id="rec", requests=[{
        "at": 1.0, "module": "fake-recorded", "url": "https://src.test/example.com",
        "status": 200, "access": "ok", "bytes": len(body), "elapsed": 0.1,
        "digest": digest, "headers": {"content-type": "application/json"},
    }])
    yield cid
    registry._REGISTRY.clear()
    registry._REGISTRY.update(saved)
    registry._imported = flag


def test_replay_reproduces_a_case_from_its_evidence(store, recorded_case):
    inv, report = replay(store, recorded_case, Config(cache_dir=None))
    assert report.clean and report.coverage == 1.0
    assert report.original == report.reproduced == 2
    assert {f.label for f in inv.findings} == {"alpha", "beta"}


def test_replay_detects_a_parser_that_stopped_reading_a_field(store, recorded_case):
    """The regression the recorded fixture exists to catch."""
    Recorded.fields = ("alpha",)
    try:
        _, report = replay(store, recorded_case, Config(cache_dir=None))
    finally:
        Recorded.fields = ("alpha", "beta")
    assert not report.clean
    assert report.drift["fake-recorded"] == (2, 1)


def test_replay_notices_tampered_evidence(store, recorded_case):
    import gzip

    digest = store.requests("rec")[0]["digest"]
    path = store.evidence.root / digest[:2] / digest
    with gzip.open(path, "wb") as fh:
        fh.write(b'{"alpha": 999}')
    _, report = replay(store, recorded_case, Config(cache_dir=None))
    assert report.corrupt == [digest]
    assert not report.clean


def test_replay_refuses_an_unknown_case(store):
    with pytest.raises(ValueError, match="no such case"):
        replay(store, "nope")


def test_replay_reports_coverage_when_a_request_was_never_recorded(store,
                                                                   recorded_case):
    Recorded.fields = ("alpha", "beta")
    store.conn.execute("UPDATE requests SET url = ? WHERE case_id = 'rec'",
                       ("https://src.test/other",))
    store.conn.commit()
    _, report = replay(store, recorded_case, Config(cache_dir=None))
    assert report.missing == ["https://src.test/example.com"]
    assert report.coverage < 1.0


def test_replay_fetcher_cannot_reach_the_network():
    """The hard rule. A replay that silently goes online proves nothing."""
    from nova_osint.core.http import Fetcher

    fetcher = ReplayFetcher({}, None)
    assert not isinstance(fetcher, Fetcher), "inheriting risks a live socket"
    resp = fetcher.get("https://example.com/")
    assert resp.status == MISSING and "not recorded" in (resp.error or "")
    assert fetcher.missing == ["https://example.com/"]


def test_replay_command_exits_nonzero_on_drift(store, recorded_case, capsys):
    Recorded.fields = ("alpha",)
    try:
        code = cmd_replay(_args(case="rec"), store, Config(cache_dir=None))
    finally:
        Recorded.fields = ("alpha", "beta")
    assert code == 1
    out = capsys.readouterr().out
    assert "lost 1" in out and "The evidence did not" in out


# ---------------------------------------------------------------------------
# evidence
# ---------------------------------------------------------------------------


def test_evidence_verifies_a_clean_store(store, recorded_case, capsys):
    assert cmd_evidence(_args(case=None, digest=None), store) == 0
    out = capsys.readouterr().out
    assert "failed verification 0" in out and "audit chain        intact" in out


def test_evidence_reports_a_tampered_blob(store, recorded_case, capsys):
    import gzip

    digest = store.requests("rec")[0]["digest"]
    with gzip.open(store.evidence.root / digest[:2] / digest, "wb") as fh:
        fh.write(b"tampered")
    assert cmd_evidence(_args(case="rec", digest=None), store) == 1
    assert digest in capsys.readouterr().out


def test_evidence_can_print_one_blob(store, recorded_case, capsys):
    digest = store.requests("rec")[0]["digest"]
    assert cmd_evidence(_args(case=None, digest=digest), store) == 0
    assert json.loads(capsys.readouterr().out) == {"alpha": 1, "beta": 2}
