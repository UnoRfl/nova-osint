"""Offline tests for collection hygiene: coalescing, budgets and the passive guard.

The passive tests matter most. ``--passive`` is a promise NOVA makes to whoever
is being scanned, and a promise a tool cannot check is not worth making - so
what is verified here is that a mislabelled module is *stopped*, not that a
correctly labelled one behaves.
"""

from __future__ import annotations

import threading
import time

import pytest

from nova_osint.core.config import Config
from nova_osint.core.engine import Engine
from nova_osint.core.http import Response
from nova_osint.core.models import ModuleStatus, ScanResult, TargetType
from nova_osint.core.opsec import (
    PassiveGuard,
    PassiveViolation,
    SingleFlight,
    budget_key,
    leak_check,
)
from nova_osint.core.registry import Module

# ---------------------------------------------------------------------------
# single flight
# ---------------------------------------------------------------------------


def test_concurrent_identical_calls_run_the_work_once():
    flight = SingleFlight()
    calls = []
    started = threading.Event()
    release = threading.Event()

    def work():
        calls.append(1)
        started.set()
        release.wait(timeout=5)
        return "answer"

    results = []
    threads = [threading.Thread(target=lambda: results.append(flight.do("k", work)))
               for _ in range(6)]
    for t in threads:
        t.start()
    started.wait(timeout=5)
    time.sleep(0.05)   # let the followers pile up behind the leader
    release.set()
    for t in threads:
        t.join(timeout=5)

    assert len(calls) == 1, "the work ran more than once"
    assert results == ["answer"] * 6
    assert flight.shared == 5


def test_different_keys_do_not_share():
    flight = SingleFlight()
    assert flight.do("a", lambda: 1) == 1
    assert flight.do("b", lambda: 2) == 2


def test_a_later_caller_does_the_work_again():
    """This is a concurrency primitive, not a cache.

    Treating it as one would give every response an unbounded lifetime, with no
    TTL and no way to refresh - which is a correctness bug wearing a
    performance-optimisation costume.
    """
    flight = SingleFlight()
    calls = []
    for _ in range(3):
        flight.do("k", lambda: calls.append(1))
    assert len(calls) == 3


def test_a_failing_leader_raises_into_its_followers_rather_than_stranding_them():
    """A follower waking to find nothing turns one failure into several.

    Each waiting module would report an empty result instead of an error, which
    is the exact confusion ModuleStatus exists to prevent.
    """
    flight = SingleFlight()
    release = threading.Event()
    started = threading.Event()

    def work():
        started.set()
        release.wait(timeout=5)
        raise RuntimeError("source exploded")

    errors = []

    def call():
        try:
            flight.do("k", work)
        except RuntimeError as exc:
            errors.append(exc)

    threads = [threading.Thread(target=call) for _ in range(4)]
    for t in threads:
        t.start()
    started.wait(timeout=5)
    time.sleep(0.05)
    release.set()
    for t in threads:
        t.join(timeout=5)
        assert not t.is_alive(), "a follower hung after the leader failed"
    assert len(errors) == 4, "every caller must see the failure"


def test_a_later_caller_after_a_failure_can_still_succeed():
    flight = SingleFlight()
    state = {"first": True}

    def work():
        if state["first"]:
            state["first"] = False
            raise RuntimeError("source exploded")
        return "recovered"

    with pytest.raises(RuntimeError):
        flight.do("k", work)
    assert flight.do("k", work) == "recovered"


# ---------------------------------------------------------------------------
# rate budgets
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url,expected", [
    ("https://api.github.com/users/x", "github.com"),
    ("https://raw.githubusercontent.com/a/b", "github.com"),
    ("https://github.com/x.keys", "github.com"),
    ("https://crt.sh/?q=x", "crt.sh"),
    ("https://cloudflare-dns.com/dns-query", "cloudflare-dns.com"),
])
def test_rate_budget_is_keyed_on_the_operator(url, expected):
    """Three hostnames, one rate limit.

    Keying on hostname lets a scan triple its request rate against one
    organisation while each individual limiter believes it is being polite -
    which is how a scan earns a 403 it cannot explain.
    """
    assert budget_key(url) == expected


def test_unknown_hosts_fall_back_to_the_registrable_domain():
    assert budget_key("https://a.b.example.co.uk/x") == "example.co.uk"


# ---------------------------------------------------------------------------
# passive guard
# ---------------------------------------------------------------------------


def test_the_guard_blocks_the_targets_own_infrastructure():
    guard = PassiveGuard("example.com")
    for url in ("https://example.com/", "https://www.example.com/robots.txt",
                "https://mail.example.com/", "http://example.com:8080/x"):
        with pytest.raises(PassiveViolation):
            guard.check(url)
    assert len(guard.blocked) == 4


def test_the_guard_allows_third_party_sources_that_know_about_the_target():
    guard = PassiveGuard("example.com")
    for url in ("https://crt.sh/?q=example.com",
                "https://dns.google/resolve?name=example.com&type=A",
                "https://web.archive.org/web/2020/http://example.com",
                "https://notexample.com/"):
        guard.check(url)          # must not raise
    assert guard.blocked == []


def test_the_guard_wraps_a_fetcher_and_refuses_at_the_call():
    class Fetcher:
        def __init__(self):
            self.asked = []

        def get(self, url, **kw):
            self.asked.append(url)
            return Response(url=url, status=200)

    inner = Fetcher()
    wrapped = PassiveGuard("example.com").wrap(inner)
    assert wrapped.get("https://crt.sh/?q=x").status == 200
    with pytest.raises(PassiveViolation):
        wrapped.get("https://example.com/")
    assert inner.asked == ["https://crt.sh/?q=x"], "the request must not go out"


class MislabelledModule(Module):
    """Declares itself passive and then fetches the target. The case that matters."""

    name = "fake-mislabelled"
    accepts = frozenset({TargetType.DOMAIN})
    active = False

    def run(self, target: str, result: ScanResult) -> None:
        self.http.get(f"https://{target}/admin")
        result.add("oops", "reached the target", source="fake")


class HonestPassiveModule(Module):
    name = "fake-honest"
    accepts = frozenset({TargetType.DOMAIN})
    active = False

    def run(self, target: str, result: ScanResult) -> None:
        result.add("third party", "looked it up elsewhere", source="fake")


def test_a_mislabelled_module_is_stopped_in_passive_mode():
    """The declaration is a promise; the guard is the enforcement."""
    cfg = Config(concurrency=2, cache_dir=None, passive_only=True)
    with Engine(cfg) as engine:
        results = engine._run_all([MislabelledModule(engine.http, cfg)],
                                  "example.com", TargetType.DOMAIN, None)
    res = results[0]
    assert res.status is ModuleStatus.SKIPPED
    assert "refusing to contact" in res.status_reason
    assert not any(f.label == "oops" for f in res.findings)


def test_an_honest_passive_module_runs_untouched():
    cfg = Config(concurrency=2, cache_dir=None, passive_only=True)
    with Engine(cfg) as engine:
        results = engine._run_all([HonestPassiveModule(engine.http, cfg)],
                                  "example.com", TargetType.DOMAIN, None)
    assert results[0].status is ModuleStatus.SUCCESS
    assert results[0].findings


def test_the_guard_is_not_installed_outside_passive_mode():
    cfg = Config(concurrency=2, cache_dir=None, passive_only=False)
    with Engine(cfg) as engine:
        results = engine._run_all([MislabelledModule(engine.http, cfg)],
                                  "example.com", TargetType.DOMAIN, None)
    # It will fail on the network in a sandbox, but it must not be SKIPPED by
    # a guard that should not exist here.
    assert results[0].status is not ModuleStatus.SKIPPED


def test_every_registered_module_that_fetches_the_target_declares_itself_active():
    """A live audit of the real module set, not of a fixture."""
    from nova_osint.core.registry import all_modules

    for cls in all_modules():
        if cls.active:
            continue
        source = cls.run.__code__.co_consts
        text = " ".join(str(c) for c in source if isinstance(c, str))
        # A passive module must never build a URL out of the target itself.
        assert "https://{" not in text.replace(" ", ""), (
            f"{cls.name} declares itself passive but formats a URL from its input")


# ---------------------------------------------------------------------------
# leak check
# ---------------------------------------------------------------------------


class _IpFetcher:
    def __init__(self, ip):
        self.ip = ip

    def get(self, url, **kw):
        import json as _json

        return Response(url=url, status=200,
                        headers={"content-type": "application/json"},
                        body=_json.dumps({"ip": self.ip}).encode())


def test_leak_check_spots_a_proxy_that_is_not_proxying():
    """A scan that silently falls back to the direct route looks fine inside."""
    out = leak_check(_IpFetcher("203.0.113.9"), _IpFetcher("203.0.113.9"))
    assert out["leaking"] is True


def test_leak_check_passes_when_the_routes_differ():
    out = leak_check(_IpFetcher("203.0.113.9"), _IpFetcher("198.51.100.4"))
    assert out["leaking"] is False
    assert out["direct"] != out["proxied"]


def test_leak_check_reports_its_own_failure_rather_than_passing():
    class Broken:
        def get(self, url, **kw):
            raise OSError("no route to host")

    out = leak_check(Broken(), _IpFetcher("1.1.1.1"))
    assert out["leaking"] is None and out["error"]
