"""The free-first ladder, provider health, and the promise that "cannot
access" never renders as "no result".

Everything here is offline by construction: the router opens no sockets, and
every step is a closure the test wrote itself.
"""

from __future__ import annotations

import dataclasses

import pytest

from nova_osint.core.acquisition import LADDER, Acquisition, Method, SourceType
from nova_osint.core.http import AccessStatus, Response, classify
from nova_osint.core.models import (
    Confidence,
    Finding,
    Investigation,
    ModuleStatus,
    ScanResult,
    TargetType,
)
from nova_osint.core.providers import (
    Availability,
    Health,
    ProviderHealth,
    ProviderInfo,
    availability_of_key,
    key_provider_rows,
)
from nova_osint.core.report import source_rows, unavailable_sources
from nova_osint.core.router import SourceRouter, Step


class FakeClock:
    """A monotonic clock the test drives, so backoff never sleeps."""

    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def step(method: Method, provider: str, value, **kw) -> Step:
    return Step(method=method, provider=provider, run=lambda: value, **kw)


# ------------------------------------------------------------------ acquisition


def test_ladder_is_ordered_cheapest_first() -> None:
    assert LADDER.index(Method.LOCAL) < LADDER.index(Method.API)
    assert LADDER.index(Method.API) < LADDER.index(Method.PAGE)
    assert LADDER.index(Method.PAGE) < LADDER.index(Method.SEARCH)
    assert LADDER.index(Method.SEARCH) < LADDER.index(Method.BROWSER)


def test_only_network_methods_count_as_network() -> None:
    assert Method.BROWSER.is_network and Method.API.is_network
    assert not Method.LOCAL.is_network
    assert not Method.CACHE.is_network


def test_acquisition_round_trips_through_storage() -> None:
    acq = Acquisition(method=Method.SEARCH, provider="mojeek",
                      url="https://example.com/a", query='"ada lovelace"',
                      status=200, source_type=SourceType.SEARCH_ENGINE)
    again = Acquisition.from_dict(acq.to_dict())
    assert again.method is Method.SEARCH
    assert again.provider == "mojeek"
    assert again.query == '"ada lovelace"'
    assert again.source_type is SourceType.SEARCH_ENGINE


def test_acquisition_tolerates_a_record_from_an_older_version() -> None:
    acq = Acquisition.from_dict({"provider": "x"})
    assert acq.method is Method.API  # a sane default, not a crash
    assert acq.source_type is SourceType.UNKNOWN


def test_acquisition_records_the_requested_url_not_the_landing_one() -> None:
    # rdap.org redirects; keying on resp.url made replay report 0% coverage.
    resp = Response(url="https://rdap.verisign.com/com/v1/domain/x",
                    status=200)
    acq = Acquisition.from_response(resp, "rdap",
                                    requested="https://rdap.org/domain/x")
    assert acq.url == "https://rdap.org/domain/x"
    assert "redirected to" in acq.detail


def test_finding_without_an_acquisition_says_so_rather_than_guessing() -> None:
    f = Finding(label="x", value="y", source="m")
    assert f.method == "unrecorded"
    assert f.to_dict()["acquisition"] is None


def test_finding_serialises_its_acquisition() -> None:
    f = Finding(label="x", value="y", source="m",
                acquisition=Acquisition(method=Method.BROWSER, provider="chrome"))
    assert f.method == "browser"
    assert f.to_dict()["acquisition"]["provider"] == "chrome"


# --------------------------------------------------------------- access status


def test_payment_and_human_action_are_their_own_refusals() -> None:
    assert classify(402) is AccessStatus.PAYMENT_REQUIRED
    assert AccessStatus.PAYMENT_REQUIRED.is_refusal
    assert AccessStatus.HUMAN_ACTION_REQUIRED.is_refusal
    # 401/403 keep their old meaning; only 402 moved.
    assert classify(403) is AccessStatus.ACCESS_DENIED


# ------------------------------------------------------------ provider health


def test_a_rate_limited_provider_is_benched_then_released() -> None:
    clock = FakeClock()
    health = ProviderHealth(clock=clock)
    health.record("crt.sh", ok=False, access=AccessStatus.RATE_LIMITED, status=429)
    assert health.health("crt.sh") is Health.RATE_LIMITED
    assert not health.usable("crt.sh")

    clock.advance(121.0)
    assert health.usable("crt.sh"), "the bench must expire, not be permanent"


def test_a_block_outlasts_a_rate_limit() -> None:
    clock = FakeClock()
    health = ProviderHealth(clock=clock)
    health.record("example", ok=False, access=AccessStatus.ACCESS_DENIED, status=403)
    clock.advance(200.0)
    assert not health.usable("example"), "a refusal is not a timing problem"


def test_a_404_does_not_mark_a_provider_unhealthy() -> None:
    health = ProviderHealth()
    health.record("api", ok=False, access=AccessStatus.NOT_FOUND, status=404)
    assert health.usable("api"), "not found is an answer, not a failure"


def test_health_counts_are_reported() -> None:
    health = ProviderHealth()
    health.record("a", ok=True)
    health.record("a", ok=False, access=AccessStatus.UNAVAILABLE)
    snap = health.snapshot()["a"]
    assert snap["attempts"] == 2 and snap["successes"] == 1 and snap["refusals"] == 1


# ---------------------------------------------------------------- the ladder


def test_the_cheapest_rung_that_answers_wins() -> None:
    router = SourceRouter()
    out = router.acquire("repos", [
        step(Method.BROWSER, "chrome", ["browser"]),
        step(Method.API, "github", ["api"]),
        step(Method.SEARCH, "mojeek", ["search"]),
    ])
    assert out.found and out.value == ["api"]
    assert out.method is Method.API
    # The browser was never tried, so it does not appear as an attempt.
    assert [a.provider for a in out.attempts] == ["github"]


def test_the_ladder_falls_through_to_search_when_the_api_is_empty() -> None:
    router = SourceRouter()
    out = router.acquire("bio", [
        step(Method.API, "wikidata", []),
        step(Method.PAGE, "site", None),
        step(Method.SEARCH, "mojeek", ["a snippet"]),
    ])
    assert out.found and out.method is Method.SEARCH
    assert [a.outcome for a in out.attempts] == ["empty", "empty", "ok"]


def test_a_refusal_is_recorded_as_refused_not_empty() -> None:
    router = SourceRouter()
    refused = Response(url="https://x", status=429)
    out = router.acquire("x", [step(Method.API, "x", refused)])
    assert not out.found
    assert out.attempts[0].outcome == "refused"
    assert out.attempts[0].health is Health.RATE_LIMITED
    assert out.unavailable, "a refusal must not read as 'asked and empty'"


def test_asked_and_empty_is_not_reported_as_unavailable() -> None:
    router = SourceRouter()
    out = router.acquire("x", [step(Method.API, "x", [])])
    assert not out.found
    assert not out.unavailable
    assert "none had it" in out.reason


def test_a_provider_that_raises_costs_only_its_own_rung() -> None:
    def boom():
        raise RuntimeError("bad parse")

    router = SourceRouter()
    out = router.acquire("x", [
        Step(method=Method.API, provider="broken", run=boom),
        step(Method.PAGE, "fallback", ["value"]),
    ])
    assert out.found and out.value == ["value"]
    assert out.attempts[0].outcome == "error"
    assert "bad parse" in out.attempts[0].detail


def test_exhausting_the_ladder_is_an_outcome_not_an_exception() -> None:
    router = SourceRouter()
    out = router.acquire("nothing", [step(Method.API, "a", None)])
    assert out.found is False
    assert out.value is None
    assert out.to_dict()["found"] is False


def test_a_need_with_no_steps_at_all_still_returns() -> None:
    out = SourceRouter().acquire("nothing", [])
    assert not out.found and out.reason == "no source available for this"


# ------------------------------------------------------------- what is skipped


def test_a_paid_rung_is_skipped_and_named_never_silently_dropped() -> None:
    router = SourceRouter()
    out = router.acquire("dns history", [
        Step(method=Method.API, provider="securitytrails",
             run=lambda: ["should not run"], paid=True),
    ])
    assert not out.found, "a paid source must not be queried by default"
    assert out.attempts[0].outcome == "skipped"
    assert out.attempts[0].health is Health.PAID
    assert "--allow-paid" in out.attempts[0].detail


def test_enabling_paid_use_lets_the_paid_rung_run() -> None:
    router = SourceRouter(allow_paid=True)
    out = router.acquire("dns history", [
        Step(method=Method.API, provider="securitytrails",
             run=lambda: ["history"], paid=True),
    ])
    assert out.found and out.value == ["history"]


def test_the_browser_rung_is_off_unless_asked_for() -> None:
    off = SourceRouter().acquire("x", [step(Method.BROWSER, "chrome", ["page"])])
    assert not off.found and off.attempts[0].outcome == "skipped"
    assert "--browser" in off.attempts[0].detail

    on = SourceRouter(allow_browser=True).acquire(
        "x", [step(Method.BROWSER, "chrome", ["page"])])
    assert on.found and on.method is Method.BROWSER


def test_a_benched_provider_is_skipped_on_the_next_need() -> None:
    clock = FakeClock()
    router = SourceRouter(health=ProviderHealth(clock=clock))
    router.acquire("first", [step(Method.API, "slow", Response(url="u", status=429))])

    calls = []

    def again():
        calls.append(1)
        return ["value"]

    out = router.acquire("second", [
        Step(method=Method.API, provider="slow", run=again),
        step(Method.PAGE, "other", ["fallback"]),
    ])
    assert calls == [], "a provider that just rate limited us must not be re-asked"
    assert out.found and out.value == ["fallback"]


def test_a_step_that_declares_itself_unavailable_is_not_run() -> None:
    def boom():  # pragma: no cover - must never be called
        raise AssertionError("ran an unavailable step")

    out = SourceRouter().acquire("x", [
        Step(method=Method.API, provider="p", run=boom,
             unavailable="needs $SOME_KEY", health=Health.NEEDS_KEY),
        step(Method.SEARCH, "mojeek", ["found anyway"]),
    ])
    assert out.found and out.value == ["found anyway"]
    assert out.attempts[0].detail == "needs $SOME_KEY"


def test_a_step_may_carry_its_own_provenance() -> None:
    acq = Acquisition(method=Method.SEARCH, provider="mojeek", query="q")
    out = SourceRouter().acquire(
        "x", [Step(method=Method.SEARCH, provider="mojeek",
                   run=lambda: (["result"], acq))])
    assert out.found and out.value == ["result"]
    assert out.acquisition is acq and out.acquisition.query == "q"


# ------------------------------------------------------- availability reporting


def test_key_costs_survive_the_trip_into_the_availability_vocabulary() -> None:
    assert availability_of_key("github") is Availability.OPTIONAL_KEY
    assert availability_of_key("securitytrails") is Availability.PAID
    assert availability_of_key("hibp") is Availability.PAID
    assert availability_of_key("virustotal") is Availability.USER_KEY
    # Declared but unread keys must not advertise capability.
    assert availability_of_key("shodan") is Availability.DISABLED


def test_key_rows_say_what_a_missing_key_actually_costs() -> None:
    rows = {label: (avail, note) for label, avail, note in key_provider_rows()}
    assert rows["SecurityTrails"][0] is Availability.PAID
    assert "paid" in rows["SecurityTrails"][1]
    assert "works anyway" in rows["GitHub"][1]


def _investigation() -> Investigation:
    ran = ScanResult(module="dns", target="example.com",
                     target_type=TargetType.DOMAIN)
    ran.add("a", "1.2.3.4", source="dns")
    empty = ScanResult(module="wayback", target="example.com",
                       target_type=TargetType.DOMAIN)
    empty.status = ModuleStatus.EMPTY
    limited = ScanResult(module="crtsh", target="example.com",
                         target_type=TargetType.DOMAIN)
    limited.status = ModuleStatus.RATE_LIMITED
    limited.status_reason = "asked us to slow down"
    inv = Investigation(target="example.com", target_type=TargetType.DOMAIN,
                        results=[ran, empty, limited])
    inv.skipped = [("virustotal", "needs $VT_API_KEY"),
                   ("securitytrails", "needs $SECURITYTRAILS_API_KEY"),
                   ("headers", "active module, passive-only mode")]
    return inv


def test_source_rows_separate_the_five_reasons_for_an_empty_result() -> None:
    rows = {name: state for name, state, _ in source_rows(_investigation())}
    assert rows["dns"] == "found"
    assert rows["wayback"] == "not found"
    assert rows["crtsh"] == "rate limited"
    assert rows["virustotal"] == "requires key"
    assert rows["securitytrails"] == "paid", \
        "a $500/mo source must not read as 'get a free key'"
    assert rows["headers"] == "not checked"


def test_unavailable_sources_excludes_the_ones_that_actually_answered() -> None:
    names = {name for name, _, _ in unavailable_sources(_investigation())}
    assert "dns" not in names and "wayback" not in names
    assert {"crtsh", "virustotal", "securitytrails", "headers"} <= names


def test_provider_health_reaches_the_availability_table() -> None:
    inv = _investigation()
    health = ProviderHealth()
    health.record("mojeek", ok=False, access=AccessStatus.RATE_LIMITED, status=429)
    inv.providers = health.snapshot()
    rows = {name: state for name, state, _ in source_rows(inv)}
    assert rows["mojeek"] == "rate limited"


def test_a_routed_need_nothing_answered_is_reported_as_unavailable() -> None:
    inv = _investigation()
    out = SourceRouter().acquire("public repositories",
                                 [step(Method.API, "gitlab",
                                       Response(url="u", status=503))])
    inv.routes = [out.to_dict()]
    rows = {name: state for name, state, _ in source_rows(inv)}
    assert rows["public repositories"] == "unavailable"


def test_every_renderer_shows_the_availability_section() -> None:
    from nova_osint.core import report

    inv = _investigation()
    md = report.render_markdown(inv)
    assert "Source availability" in md and "securitytrails" in md
    html = report.render_html(inv)
    assert "Source availability" in html
    csv_out = report.render_csv(inv)
    assert "source availability" in csv_out or "securitytrails" in csv_out
    assert "method" in csv_out.splitlines()[0]


@pytest.mark.parametrize("status,expected", [
    (429, Health.RATE_LIMITED),
    (403, Health.BLOCKED),
    (451, Health.BLOCKED),
    (402, Health.PAID),
    (500, Health.UNAVAILABLE),
    (0, Health.UNAVAILABLE),
])
def test_http_outcomes_map_onto_provider_health(status: int, expected: Health) -> None:
    health = ProviderHealth(clock=FakeClock())
    got = health.record("p", ok=False, access=classify(status), status=status)
    assert got is expected


def test_provider_info_is_a_statement_not_a_mutable_state() -> None:
    info = ProviderInfo(name="x", label="X", availability=Availability.FREE,
                        method=Method.API)
    with pytest.raises(dataclasses.FrozenInstanceError):
        info.name = "y"  # type: ignore[misc]


def test_confidence_and_method_are_independent() -> None:
    # An authoritative registry read through a browser is still authoritative.
    f = Finding(label="registrant", value="Acme", source="rdap",
                confidence=Confidence.CONFIRMED,
                acquisition=Acquisition(method=Method.BROWSER, provider="chrome"))
    assert f.confidence is Confidence.CONFIRMED and f.method == "browser"


def test_every_declared_key_states_its_availability() -> None:
    """The one that stops a new key being added with a free-text cost line
    and no machine-readable price, which is how SecurityTrails was briefly
    advertised as free."""
    from nova_osint.core.config import KEY_INFO

    for name, info in KEY_INFO.items():
        declared = info.get("availability")
        assert declared, f"{name} does not declare an availability"
        assert Availability(declared), f"{name}: {declared!r} is not a known availability"
