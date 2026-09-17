"""Offline tests for the case store, evidence store and audit chain.

Everything runs against a ``tmp_path`` store; nothing touches the user's real
case directory and nothing touches the network.
"""

from __future__ import annotations

import gzip
import json

import pytest

from nova_osint.core.entities import Entity, EntityType
from nova_osint.core.graph import EntityGraph, Observation
from nova_osint.core.models import (
    Confidence,
    Investigation,
    ModuleStatus,
    ScanResult,
    Severity,
    TargetType,
)
from nova_osint.core.store import AuditLog, CaseStore, EvidenceStore, finding_id


@pytest.fixture()
def store(tmp_path):
    with CaseStore(tmp_path / "cases") as s:
        yield s


def _investigation(target="example.com", *, mx="alt1.aspmx.l.google.com",
                   extra=None, status=ModuleStatus.SUCCESS):
    inv = Investigation(target=target, target_type=TargetType.DOMAIN)
    res = ScanResult(module="domain", target=target, target_type=TargetType.DOMAIN)
    res.add("mail exchangers", mx, source="doh")
    res.add("registrar", "Example Registrar", source="rdap",
            confidence=Confidence.CONFIRMED, severity=Severity.INFO)
    for label, value in (extra or {}).items():
        res.add(label, value, source="test")
    res.status = status
    inv.results.append(res)
    return inv.finish()


def _graph(target="example.com"):
    seed = Entity.make(EntityType.DOMAIN, target)
    g = EntityGraph(seed)
    ip = Entity.make(EntityType.IP, "203.0.113.10")
    g.connect(seed, ip, "resolves-to", Observation("dns-a", "domain",
                                                   url="https://dns.google/resolve"))
    g.rescore()
    return g


# ---------------------------------------------------------------------------
# evidence store
# ---------------------------------------------------------------------------


def test_evidence_round_trips(tmp_path):
    ev = EvidenceStore(tmp_path / "ev")
    digest = ev.put(b"<html>hello</html>")
    assert digest and ev.get(digest) == b"<html>hello</html>"
    assert ev.verify(digest)


def test_identical_bodies_are_stored_once(tmp_path):
    ev = EvidenceStore(tmp_path / "ev")
    a = ev.put("same bytes")
    b = ev.put("same bytes")
    assert a == b
    assert ev.size()[0] == 1


def test_evidence_is_compressed_on_disk(tmp_path):
    ev = EvidenceStore(tmp_path / "ev")
    digest = ev.put(b"a" * 10_000)
    path = ev.root / digest[:2] / digest
    assert path.stat().st_size < 1_000
    with gzip.open(path, "rb") as fh:
        assert fh.read() == b"a" * 10_000


def test_corrupted_evidence_fails_verification(tmp_path):
    ev = EvidenceStore(tmp_path / "ev")
    digest = ev.put(b"original")
    path = ev.root / digest[:2] / digest
    with gzip.open(path, "wb") as fh:
        fh.write(b"tampered")
    assert not ev.verify(digest), "a rewritten blob must not pass its own digest"


def test_empty_body_is_not_stored(tmp_path):
    assert EvidenceStore(tmp_path / "ev").put(b"") is None


def test_missing_evidence_reads_as_none(tmp_path):
    assert EvidenceStore(tmp_path / "ev").get("f" * 64) is None


# ---------------------------------------------------------------------------
# audit chain
# ---------------------------------------------------------------------------


def test_audit_chain_verifies(tmp_path):
    a = AuditLog(tmp_path / "audit.log")
    a.append("scan", target="example.com")
    a.append("scan", target="other.test")
    intact, count = a.verify()
    assert intact and count == 2


def test_audit_chain_detects_an_edited_line(tmp_path):
    path = tmp_path / "audit.log"
    a = AuditLog(path)
    a.append("scan", target="example.com")
    a.append("scan", target="other.test")
    a.append("scan", target="third.test")
    lines = path.read_text("utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["target"] = "rewritten.test"
    lines[1] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", "utf-8")
    intact, index = a.verify()
    assert not intact and index == 2, "the break shows at the line after the edit"


def test_audit_chain_detects_a_deleted_line(tmp_path):
    path = tmp_path / "audit.log"
    a = AuditLog(path)
    for t in ("a.test", "b.test", "c.test"):
        a.append("scan", target=t)
    lines = path.read_text("utf-8").splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n", "utf-8")
    assert a.verify()[0] is False


def test_empty_audit_log_is_intact(tmp_path):
    assert AuditLog(tmp_path / "nothing.log").verify() == (True, 0)


# ---------------------------------------------------------------------------
# saving and reading cases
# ---------------------------------------------------------------------------


def test_save_and_reload_a_case(store):
    cid = store.save(_investigation(), _graph())
    rec = store.case(cid)
    assert rec is not None
    assert rec.target == "example.com" and rec.target_type == "domain"
    assert rec.summary["findings"] == 2
    assert {r["label"] for r in store.findings(cid)} == {"mail exchangers", "registrar"}


def test_case_is_findable_by_id_prefix(store):
    cid = store.save(_investigation(), _graph())
    assert store.case(cid[:8]) is not None and store.case(cid[:8]).id == cid


def test_graph_round_trips_through_sqlite(store):
    g = _graph()
    cid = store.save(_investigation(), g)
    back = store.graph(cid)
    assert set(back.nodes) == set(g.nodes)
    assert back.seed == g.seed
    edge = next(iter(back.edges.values()))
    assert edge.observations[0].kind == "dns-a"
    assert edge.observations[0].url == "https://dns.google/resolve"
    assert back.nodes[g.seed].score == 1.0


def test_module_statuses_are_recorded_including_skips(store):
    inv = _investigation(status=ModuleStatus.RATE_LIMITED)
    inv.skipped.append(("virustotal", "needs $VIRUSTOTAL_API_KEY"))
    cid = store.save(inv, _graph())
    statuses = store.statuses(cid)
    assert statuses["domain"][0] == "rate limited"
    assert statuses["virustotal"] == ("skipped", "needs $VIRUSTOTAL_API_KEY")


def test_requests_are_recorded_even_when_they_found_nothing(store):
    cid = store.save(_investigation(), _graph(), requests=[
        {"at": 1.0, "module": "domain", "url": "https://crt.sh/?q=x", "status": 503,
         "access": "unavailable", "bytes": 0, "elapsed": 2.1},
    ])
    rows = store.requests(cid)
    assert len(rows) == 1 and rows[0]["status"] == 503
    assert rows[0]["access"] == "unavailable"


def test_saving_writes_an_audit_entry(store):
    cid = store.save(_investigation(), _graph())
    entries = store.audit.entries()
    assert entries[-1]["action"] == "scan" and entries[-1]["case"] == cid
    assert store.audit.verify()[0]


def test_cases_are_listed_newest_first(store):
    a = store.save(_investigation(target="a.test"), _graph("a.test"))
    b = store.save(_investigation(target="b.test"), _graph("b.test"))
    ids = [c.id for c in store.cases()]
    assert set(ids) == {a, b}
    assert store.cases(target="a.test")[0].id == a


# ---------------------------------------------------------------------------
# diffing
# ---------------------------------------------------------------------------


def test_finding_id_ignores_the_value_so_a_change_reads_as_a_change(store):
    old = store.save(_investigation(mx="old.mx.test"), _graph(), case_id="old")
    new = store.save(_investigation(mx="new.mx.test"), _graph(), case_id="new")
    changes = store.diff(old, new)
    mx = [c for c in changes if "mail exchangers" in c.key]
    assert len(mx) == 1 and mx[0].kind == "changed"
    assert mx[0].before == "old.mx.test" and mx[0].after == "new.mx.test"


def test_diff_reports_added_and_removed_findings(store):
    old = store.save(_investigation(), _graph(), case_id="old")
    new = store.save(_investigation(extra={"new thing": "value"}), _graph(),
                     case_id="new")
    kinds = {(c.kind, c.key) for c in store.diff(old, new)}
    assert ("added", "domain: new thing") in kinds
    assert ("removed", "domain: new thing") in {
        (c.kind, c.key) for c in store.diff(new, old)}


def test_identical_scans_diff_to_nothing(store):
    old = store.save(_investigation(), _graph(), case_id="old")
    new = store.save(_investigation(), _graph(), case_id="new")
    assert store.diff(old, new) == []


def test_new_entities_show_up_in_the_diff(store):
    g2 = _graph()
    seed = Entity.make(EntityType.DOMAIN, "example.com")
    extra = Entity.make(EntityType.HOST, "mail.example.com")
    g2.connect(seed, extra, "subdomain-of", Observation("cert-san", "crtsh"))
    g2.rescore()
    old = store.save(_investigation(), _graph(), case_id="old")
    new = store.save(_investigation(), g2, case_id="new")
    added = {c.key for c in store.diff(old, new) if c.scope == "entity" and c.kind == "added"}
    assert "host:mail.example.com" in added


def test_a_module_going_blocked_is_a_coverage_change_not_a_finding_loss(store):
    """The failure this exists to prevent: 'could not look' reading as 'nothing there'."""
    old = store.save(_investigation(status=ModuleStatus.SUCCESS), _graph(), case_id="old")
    new = store.save(_investigation(status=ModuleStatus.BLOCKED), _graph(), case_id="new")
    status_changes = [c for c in store.diff(old, new) if c.scope == "status"]
    assert len(status_changes) == 1
    assert status_changes[0].before == "success" and status_changes[0].after == "blocked"


# ---------------------------------------------------------------------------
# cross-case correlation
# ---------------------------------------------------------------------------


def test_link_finds_entities_two_cases_share(store):
    shared = Entity.make(EntityType.EMAIL, "admin@example.com")
    ga, gb = _graph("a.test"), _graph("b.test")
    for g, seed_name in ((ga, "a.test"), (gb, "b.test")):
        seed = Entity.make(EntityType.DOMAIN, seed_name)
        g.connect(seed, shared, "contact", Observation("rdap-contact", "domain"))
        g.rescore()
    a = store.save(_investigation(target="a.test"), ga, case_id="a")
    b = store.save(_investigation(target="b.test"), gb, case_id="b")
    linked = store.link(a, b)
    values = {row["value"] for row in linked}
    assert "admin@example.com" in values
    assert not next(r for r in linked if r["value"] == "admin@example.com")[
        "shared_infrastructure"]


def test_link_flags_shared_infrastructure_rather_than_hiding_it(store):
    cdn = Entity.make(EntityType.IP, "198.51.100.1")
    graphs = []
    for name in ("a.test", "b.test"):
        seed = Entity.make(EntityType.DOMAIN, name)
        g = EntityGraph(seed)
        g.connect(seed, cdn, "resolves-to", Observation("dns-a", "domain"))
        for i in range(20):
            other = Entity.make(EntityType.DOMAIN, f"tenant{i}.test")
            g.connect(cdn, other, "hosts", Observation("shared-hosting", "ip"))
        g.rescore()
        graphs.append(g)
    a = store.save(_investigation(target="a.test"), graphs[0], case_id="a")
    b = store.save(_investigation(target="b.test"), graphs[1], case_id="b")
    row = next(r for r in store.link(a, b) if r["value"] == "198.51.100.1")
    assert row["shared_infrastructure"] is True


def test_seen_elsewhere_finds_the_other_case(store):
    shared = Entity.make(EntityType.EMAIL, "admin@example.com")
    ids = []
    for name in ("a.test", "b.test"):
        seed = Entity.make(EntityType.DOMAIN, name)
        g = EntityGraph(seed)
        g.connect(seed, shared, "contact", Observation("rdap-contact", "domain"))
        g.rescore()
        ids.append(store.save(_investigation(target=name), g, case_id=name))
    others = store.seen_elsewhere(shared, exclude=ids[0])
    assert [c.id for c in others] == [ids[1]]


# ---------------------------------------------------------------------------
# housekeeping
# ---------------------------------------------------------------------------


def test_forget_removes_the_case_and_its_rows(store):
    cid = store.save(_investigation(), _graph())
    assert store.forget(cid) is True
    assert store.case(cid) is None
    assert store.findings(cid) == []
    assert store.forget(cid) is False


def test_stats_reports_the_store(store):
    store.save(_investigation(), _graph())
    store.evidence.put(b"some page")
    s = store.stats()
    assert s["cases"] == 1 and s["findings"] == 2 and s["entities"] == 2
    assert s["evidence_files"] == 1 and s["audit_intact"] is True


def test_a_newer_schema_is_refused_rather_than_corrupted(tmp_path):
    store = CaseStore(tmp_path / "cases")
    store.conn.execute("PRAGMA user_version=999")
    store.conn.commit()
    store.close()
    with pytest.raises(RuntimeError, match="schema v999"):
        _ = CaseStore(tmp_path / "cases").conn


def test_finding_id_is_stable_across_runs():
    from nova_osint.core.models import Finding

    f = Finding(label="mail exchangers", value="a", source="doh")
    g = Finding(label="Mail Exchangers", value="b", source="DOH")
    assert finding_id("domain", f) == finding_id("domain", g)


def test_concurrent_writes_of_identical_bytes_all_succeed(tmp_path):
    """Two modules filing the same shared response must not race each other.

    Single-flight makes them share one response and each recorder files it, so
    simultaneous identical writes are the normal case. With a shared temp name
    one thread renamed the file out from under the other, whose replace then
    failed on Windows - the finding survived and its evidence silently did not.
    """
    import threading

    ev = EvidenceStore(tmp_path / "ev")
    data = b"x" * 5000
    results, errors = [], []

    def store():
        try:
            results.append(ev.put(data))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=store) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert not errors
    assert all(r is not None for r in results), "a concurrent write was dropped"
    assert len(set(results)) == 1
    assert ev.verify(results[0])
    assert ev.size()[0] == 1, "content addressing must still deduplicate"
    leftovers = [p.name for p in ev.root.rglob("*.part")]
    assert leftovers == [], f"temp files left behind: {leftovers}"
