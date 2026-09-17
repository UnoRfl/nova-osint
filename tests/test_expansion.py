"""Offline tests for frontier expansion.

Every module here is a fake that returns canned entities without touching the
network, so what is under test is purely the engine's decision-making: what it
chooses to look at next, when it stops, and what it says about what it skipped.
"""

from __future__ import annotations

import pytest

from nova_osint.core import registry
from nova_osint.core.config import Config
from nova_osint.core.engine import Budget, Engine
from nova_osint.core.entities import EntityType
from nova_osint.core.graph import EVIDENCE
from nova_osint.core.models import ModuleStatus, ScanResult, TargetType
from nova_osint.core.registry import Module
from nova_osint.core.store import EvidenceStore


@pytest.fixture()
def registry_of():
    """Swap the module registry for the duration of one test.

    The registry is global by design - registering is a decorator, which is what
    keeps adding a source to one file. That makes isolating it the test's job.
    """
    saved, saved_flag = dict(registry._REGISTRY), registry._imported

    def install(*classes):
        registry._REGISTRY.clear()
        for cls in classes:
            registry._REGISTRY[cls.name] = cls
        registry._imported = True

    yield install
    registry._REGISTRY.clear()
    registry._REGISTRY.update(saved)
    registry._imported = saved_flag


def _engine(**cfg):
    cfg.setdefault("concurrency", 4)
    cfg.setdefault("cache_dir", None)
    return Engine(Config(**cfg))


# ---------------------------------------------------------------------------
# fake modules
# ---------------------------------------------------------------------------


class DomainToEmail(Module):
    """domain -> the registry contact on it."""

    name = "fake-domain"
    accepts = frozenset({TargetType.DOMAIN})

    def run(self, target: str, result: ScanResult) -> None:
        result.add("registrar", "Test Registrar", source="fake")
        result.entity(EntityType.EMAIL, f"admin@{target}", relation="contact",
                      evidence="rdap-contact", url="https://rdap.test/x")


class EmailToUsername(Module):
    """email -> the handle that signs its commits."""

    name = "fake-email"
    accepts = frozenset({TargetType.EMAIL})

    def run(self, target: str, result: ScanResult) -> None:
        local = target.split("@")[0]
        result.entity(EntityType.USERNAME, local, relation="same-as",
                      evidence="commit-email")


class UsernameLeaf(Module):
    name = "fake-username"
    accepts = frozenset({TargetType.USERNAME})

    def run(self, target: str, result: ScanResult) -> None:
        result.add("profile", f"https://example.test/{target}", source="fake")


class LegacyPivot(Module):
    """Still on the old API: emits a Pivot and no entity."""

    name = "fake-legacy"
    accepts = frozenset({TargetType.DOMAIN})

    def run(self, target: str, result: ScanResult) -> None:
        result.pivot("203.0.113.7", TargetType.IP, "resolved during the scan")


class IpLeaf(Module):
    name = "fake-ip"
    accepts = frozenset({TargetType.IP})

    def run(self, target: str, result: ScanResult) -> None:
        result.add("asn", "AS64496", source="fake")


class Counter(Module):
    """Records every target it was pointed at, to catch duplicate work."""

    name = "fake-counter"
    accepts = frozenset({TargetType.DOMAIN, TargetType.EMAIL})
    seen: list[str] = []

    def run(self, target: str, result: ScanResult) -> None:
        Counter.seen.append(target)
        result.entity(EntityType.EMAIL, "shared@example.com", relation="contact",
                      evidence="rdap-contact")


class CdnFanout(Module):
    """One shared address answering for a great many unrelated names."""

    name = "fake-cdn"
    accepts = frozenset({TargetType.DOMAIN})

    def run(self, target: str, result: ScanResult) -> None:
        cdn = result.entity(EntityType.IP, "198.51.100.1", relation="resolves-to",
                            evidence="dns-a")
        for i in range(60):
            tenant = result.entity(EntityType.DOMAIN, f"tenant{i}.test",
                                   relation="hosts", evidence="shared-hosting")
            if cdn is not None and tenant is not None:
                result.link(cdn, tenant, "hosts", "shared-hosting")


class Exploder(Module):
    """Emits a new domain every time, so the walk never runs out of leads."""

    name = "fake-explode"
    accepts = frozenset({TargetType.DOMAIN})
    counter = 0

    def run(self, target: str, result: ScanResult) -> None:
        for _ in range(3):
            Exploder.counter += 1
            result.entity(EntityType.DOMAIN, f"n{Exploder.counter}.test",
                          relation="same-as", evidence="spki-shared")


class Broken(Module):
    name = "fake-broken"
    accepts = frozenset({TargetType.EMAIL})

    def run(self, target: str, result: ScanResult) -> None:
        raise RuntimeError("module is broken")


# ---------------------------------------------------------------------------
# the walk
# ---------------------------------------------------------------------------


def test_a_plain_scan_still_builds_a_graph(registry_of):
    registry_of(DomainToEmail)
    with _engine() as e:
        inv = e.scan("example.com")
    assert inv.graph is not None and len(inv.graph) == 2
    assert "email:admin@example.com" in inv.graph.nodes
    assert inv.graph.nodes[inv.graph.seed].score == 1.0


def test_expansion_walks_two_hops_along_the_evidence(registry_of):
    registry_of(DomainToEmail, EmailToUsername, UsernameLeaf)
    with _engine() as e:
        inv = e.investigate("example.com", budget=Budget(max_depth=3))
    eids = set(inv.graph.nodes)
    assert eids == {"domain:example.com", "email:admin@example.com", "username:admin"}
    assert inv.graph.nodes["username:admin"].depth == 2
    # ...and the leaf module actually ran against the handle it discovered.
    assert any(r.module == "fake-username" and r.target == "admin" for r in inv.results)
    assert any(f.label == "profile" for f in inv.findings)


def test_edges_carry_the_evidence_the_module_declared(registry_of):
    registry_of(DomainToEmail, EmailToUsername, UsernameLeaf)
    with _engine() as e:
        inv = e.investigate("example.com")
    edge = next(iter(inv.graph.between("domain:example.com", "email:admin@example.com")))
    assert edge.observations[0].kind == "rdap-contact"
    assert edge.observations[0].url == "https://rdap.test/x"
    assert edge.llr == pytest.approx(EVIDENCE["rdap-contact"])
    assert edge.grade.startswith("B")


def test_legacy_pivots_still_expand_but_score_lower(registry_of):
    registry_of(LegacyPivot, IpLeaf)
    with _engine() as e:
        inv = e.investigate("example.com")
    assert "ip:203.0.113.7" in inv.graph.nodes
    assert any(r.module == "fake-ip" for r in inv.results)
    edge = next(iter(inv.graph.between("domain:example.com", "ip:203.0.113.7")))
    assert edge.observations[0].kind == "pivot-derived"
    assert edge.llr < EVIDENCE["rdap-contact"]


def test_the_same_module_never_runs_twice_on_one_entity(registry_of):
    """Two paths to one entity is normal; two scans of it is wasted budget."""
    Counter.seen = []
    registry_of(Counter)
    with _engine() as e:
        e.investigate("example.com", budget=Budget(max_depth=3))
    assert sorted(Counter.seen) == ["example.com", "shared@example.com"]


def test_a_module_that_raises_mid_walk_does_not_stop_it(registry_of):
    registry_of(DomainToEmail, Broken, EmailToUsername, UsernameLeaf)
    with _engine() as e:
        inv = e.investigate("example.com", budget=Budget(max_depth=3))
    statuses = {(r.module, r.status) for r in inv.results}
    assert ("fake-broken", ModuleStatus.FAILED) in statuses
    assert "username:admin" in inv.graph.nodes, "the walk continued past the failure"


def test_shared_hosting_fanout_is_recorded_but_never_expanded(registry_of):
    """End to end, through the engine, of the property the graph guarantees."""
    registry_of(CdnFanout)
    with _engine() as e:
        inv = e.investigate("example.com", budget=Budget(max_depth=3, max_entities=500))
    assert len(inv.graph) == 62, "every co-tenant is still recorded"
    expanded = set(inv.expansion.expanded)
    assert not any(eid.startswith("domain:tenant") for eid in expanded)


# ---------------------------------------------------------------------------
# budgets
# ---------------------------------------------------------------------------


def test_module_run_cap_stops_the_walk_and_says_so(registry_of):
    Exploder.counter = 0
    registry_of(Exploder)
    with _engine() as e:
        inv = e.investigate("example.com",
                            budget=Budget(max_module_runs=5, max_entities=1000,
                                          max_depth=9))
    assert inv.expansion.module_runs >= 5
    assert "module-run cap" in inv.expansion.stopped_by


def test_entity_cap_stops_the_walk_and_says_so(registry_of):
    Exploder.counter = 0
    registry_of(Exploder)
    with _engine() as e:
        inv = e.investigate("example.com",
                            budget=Budget(max_entities=6, max_module_runs=999,
                                          max_depth=9))
    assert "entity cap" in inv.expansion.stopped_by


def test_depth_limit_bounds_the_walk(registry_of):
    registry_of(DomainToEmail, EmailToUsername, UsernameLeaf)
    with _engine() as e:
        inv = e.investigate("example.com", budget=Budget(max_depth=1))
    assert "username:admin" in inv.graph.nodes, "still discovered..."
    assert not any(r.target == "admin" for r in inv.results), "...but never scanned"


def test_truncated_walks_name_what_they_did_not_reach(registry_of):
    Exploder.counter = 0
    registry_of(Exploder)
    with _engine() as e:
        inv = e.investigate("example.com",
                            budget=Budget(max_module_runs=3, max_entities=1000,
                                          max_depth=9))
    assert inv.expansion.unexplored, "a cut-off investigation must say it was cut off"
    scores = [s for _, s in inv.expansion.unexplored]
    assert scores == sorted(scores, reverse=True)
    assert len({e for e, _ in inv.expansion.unexplored}) == len(scores)


def test_quick_and_deep_are_real_presets():
    assert Budget.quick().max_entities < Budget().max_entities < Budget.deep().max_entities
    assert Budget.quick().max_depth <= Budget().max_depth <= Budget.deep().max_depth


def test_budget_can_restrict_which_entity_kinds_get_looked_up(registry_of):
    registry_of(DomainToEmail, EmailToUsername, UsernameLeaf)
    with _engine() as e:
        inv = e.investigate("example.com", budget=Budget(
            max_depth=3, types=frozenset({EntityType.DOMAIN})))
    assert not any(r.module == "fake-email" for r in inv.results)


def test_an_unrecognisable_target_expands_to_nothing_without_raising(registry_of):
    registry_of(DomainToEmail)
    with _engine() as e:
        inv = e.investigate("!!! not a target !!!")
    assert inv.results == [] and len(inv.graph) == 0


# ---------------------------------------------------------------------------
# provenance
# ---------------------------------------------------------------------------


class Fetches(Module):
    """Makes one real-looking request through the recorder, against a dead host."""

    name = "fake-fetch"
    accepts = frozenset({TargetType.DOMAIN})

    def run(self, target: str, result: ScanResult) -> None:
        self.http.get("http://127.0.0.1:9/never")


def test_every_request_is_logged_even_when_it_fails(registry_of):
    registry_of(Fetches)
    with _engine(timeout=0.4, retries=0) as e:
        inv = e.investigate("example.com")
    assert len(inv.requests) == 1
    row = inv.requests[0]
    assert row["module"] == "fake-fetch" and row["url"].endswith("/never")
    assert row["access"] and "at" in row


def test_response_bodies_are_filed_in_the_evidence_store(tmp_path, registry_of):
    """The chain-of-custody link: a finding points at the bytes it came from."""
    from nova_osint.core.engine import _ModuleHttp
    from nova_osint.core.http import Response

    ev = EvidenceStore(tmp_path / "ev")
    recorder = _ModuleHttp(None, "fake", ev)
    recorder._record(Response(url="https://x.test/", status=200, body=b"<html>hi</html>"))
    digest = recorder.ledger[0]["digest"]
    assert digest and ev.get(digest) == b"<html>hi</html>"
    assert ev.verify(digest)


def test_investigation_serialises_its_graph_and_expansion(registry_of):
    registry_of(DomainToEmail, EmailToUsername, UsernameLeaf)
    with _engine() as e:
        inv = e.investigate("example.com")
    d = inv.to_dict()
    assert d["summary"]["entities"] == 3 and d["summary"]["edges"] == 2
    assert d["graph"]["seed"] == "domain:example.com"
    assert d["expansion"]["stopped_by"] == "frontier exhausted"
    assert d["expansion"]["module_runs"] >= 3
