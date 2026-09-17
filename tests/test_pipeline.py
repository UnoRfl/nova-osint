"""Offline tests for the configuration, retry, normalisation and status layers.

Nothing here touches the network. Where a test needs an HTTP response it builds
a :class:`Response` by hand, which is also the cheapest way to pin down how the
engine reacts to a source that refuses.
"""

from __future__ import annotations

import email.utils
import json
import logging
import threading
import time
from pathlib import Path

import pytest

from nova_osint.core import logging_config, normalizer
from nova_osint.core.config import Config, ConfigManager
from nova_osint.core.engine import Engine, _ModuleHttp
from nova_osint.core.http import AccessStatus, Fetcher, Response, _has_auth, classify
from nova_osint.core.models import (
    Confidence,
    Investigation,
    ModuleStatus,
    ScanResult,
    Severity,
    TargetType,
)
from nova_osint.core.registry import Module
from nova_osint.core.report import RENDERERS, confidence_counts, status_rows
from nova_osint.core.retry import RetryPolicy, parse_retry_after

# --------------------------------------------------------------------- retries


@pytest.mark.parametrize(
    "header,expected",
    [("120", 120.0), ("0", 0.0), ("  30 ", 30.0), ("not-a-number", None), ("", None), (None, None)],
)
def test_parse_retry_after_seconds(header: str | None, expected: float | None) -> None:
    assert parse_retry_after(header) == expected


def test_parse_retry_after_http_date() -> None:
    now = time.time()
    when = email.utils.formatdate(now + 45, usegmt=True)
    parsed = parse_retry_after(when, now=now)
    assert parsed is not None and 43 <= parsed <= 47


def test_permanent_failures_are_not_retried() -> None:
    policy = RetryPolicy(max_retries=3)
    for status in (400, 401, 403, 404, 410, 451):
        assert not policy.should_retry(attempt=1, status=status, error=None), status


def test_transient_failures_are_retried_until_the_limit() -> None:
    policy = RetryPolicy(max_retries=2)
    assert policy.should_retry(attempt=1, status=429, error=None)
    assert policy.should_retry(attempt=2, status=503, error=None)
    assert not policy.should_retry(attempt=3, status=503, error=None)
    # A transport failure has status 0 and an error string.
    assert policy.should_retry(attempt=1, status=0, error="connection reset")
    assert not policy.should_retry(attempt=1, status=0, error=None)


def test_backoff_is_exponential() -> None:
    policy = RetryPolicy(jitter=0.0)
    assert policy.delay(1) == 2.0
    assert policy.delay(2) == 4.0
    assert policy.delay(3) == 8.0


def test_retry_after_beats_our_own_curve() -> None:
    policy = RetryPolicy(jitter=0.0)
    assert policy.delay(1, "17") == 17.0
    # ...but we will not block a scan for an hour on one source's say-so.
    assert policy.delay(1, "9999") == policy.retry_after_cap
    assert policy.exceeds_cap("9999")
    assert not policy.exceeds_cap("5")


# ------------------------------------------------------------- access statuses


@pytest.mark.parametrize(
    "status,expected",
    [
        (200, AccessStatus.OK),
        (301, AccessStatus.OK),
        (404, AccessStatus.NOT_FOUND),
        (429, AccessStatus.RATE_LIMITED),
        (403, AccessStatus.ACCESS_DENIED),
        (401, AccessStatus.ACCESS_DENIED),
        (451, AccessStatus.BLOCKED),
        (503, AccessStatus.UNAVAILABLE),
        (418, AccessStatus.CLIENT_ERROR),
        (0, AccessStatus.UNAVAILABLE),
    ],
)
def test_classify(status: int, expected: AccessStatus) -> None:
    assert classify(status, "boom" if status == 0 else None) is expected


def test_refusals_are_named_not_swallowed() -> None:
    blocked = Response(url="u", status=403)
    assert blocked.access.is_refusal
    assert "access denied" in blocked.describe()
    assert not Response(url="u", status=200).access.is_refusal


def test_authenticated_requests_are_never_cached(tmp_path: Path) -> None:
    # A response fetched with someone's API key must not land in a shared cache
    # where a later keyless run would read it back.
    assert _has_auth({"hibp-api-key": "secret"})
    assert _has_auth({"Authorization": "Bearer x"})
    assert not _has_auth({"Accept": "application/json"})


def test_fetcher_map_does_not_deadlock_when_nested() -> None:
    """A module fanning out from inside a worker used to hang the whole scan."""
    fetch = Fetcher(concurrency=2, per_host_delay=0)
    try:
        done: list[list[int]] = []

        def inner(x: int) -> int:
            return x * 2

        def outer(_: int) -> int:
            return sum(fetch.map(inner, range(5)))

        worker = threading.Thread(
            target=lambda: done.append(fetch.map(outer, range(6))), daemon=True
        )
        worker.start()
        worker.join(timeout=15)
        assert done, "nested fan-out deadlocked"
        assert done[0] == [20] * 6
    finally:
        fetch.close()


# ---------------------------------------------------------------- normaliser


def test_clean_text_collapses_whitespace_and_controls() -> None:
    assert normalizer.clean_text("  a\t\tb\r\nc \x00 ") == "a b c"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("HTTPS://Example.COM:443/Path", "https://example.com/Path"),
        ("http://example.com.:80/x", "http://example.com/x"),
        ("https://example.com/a#Adobe", "https://example.com/a#Adobe"),
        ("mailto:a@example.com", "mailto:a@example.com"),
        ("", None),
        (None, None),
    ],
)
def test_normalize_url(raw: str | None, expected: str | None) -> None:
    assert normalizer.normalize_url(raw) == expected


def test_normalizer_drops_duplicates_and_empties_but_keeps_zero() -> None:
    res = ScanResult(module="m", target="t", target_type=TargetType.DOMAIN)
    res.add("ports", 0, source="shodan")           # a real answer, must survive
    res.add("name", "  Acme  ", source="rdap")
    res.add("name", "Acme", source="rdap")          # duplicate after cleaning
    res.add("name", "Acme", source="certspotter")   # different source: corroboration
    res.add("empty", "", source="rdap")
    res.add("nothing", [], source="rdap")
    report = normalizer.DataNormalizer().normalize(res)

    labels = [(f.label, f.value, f.source) for f in res.findings]
    assert ("ports", 0, "shodan") in labels
    assert ("name", "Acme", "rdap") in labels
    assert ("name", "Acme", "certspotter") in labels
    assert report.dropped_duplicate == 1
    assert report.dropped_empty == 2


def test_normalizer_never_upgrades_confidence() -> None:
    res = ScanResult(module="m", target="t", target_type=TargetType.DOMAIN)
    res.add("guess", "Jane Doe", source="heuristic", confidence=Confidence.POSSIBLE)
    normalizer.DataNormalizer().normalize(res)
    assert res.findings[0].confidence is Confidence.POSSIBLE


def test_normalizer_deduplicates_pivots() -> None:
    res = ScanResult(module="m", target="t", target_type=TargetType.DOMAIN)
    res.pivot("A.Example.com.", TargetType.DOMAIN, "one")
    res.pivot("a.example.com", TargetType.DOMAIN, "two")
    normalizer.DataNormalizer().normalize(res)
    assert [p.target for p in res.pivots] == ["a.example.com"]


# ------------------------------------------------------------- module status


def test_degrade_keeps_the_worst_status() -> None:
    res = ScanResult(module="m", target="t", target_type=TargetType.DOMAIN)
    res.degrade(ModuleStatus.PARTIAL, "one source down")
    res.degrade(ModuleStatus.RATE_LIMITED, "throttled")
    res.degrade(ModuleStatus.PARTIAL, "another source down")  # must not win
    assert res.status is ModuleStatus.RATE_LIMITED
    assert res.status_reason == "throttled"


def test_investigation_duration_is_frozen_once_finished() -> None:
    inv = Investigation(target="t", target_type=TargetType.DOMAIN)
    inv.finish()
    first = inv.duration
    time.sleep(0.05)
    assert inv.duration == first  # rendering must not inflate the scan time


class _Boom(Module):
    name = "boom"
    accepts = frozenset({TargetType.DOMAIN})

    def run(self, target: str, result: ScanResult) -> None:
        raise RuntimeError("module is broken")


class _Fine(Module):
    name = "fine"
    accepts = frozenset({TargetType.DOMAIN})

    def run(self, target: str, result: ScanResult) -> None:
        result.add("ok", "yes", source="test")


class _Quiet(Module):
    name = "quiet"
    accepts = frozenset({TargetType.DOMAIN})

    def run(self, target: str, result: ScanResult) -> None:
        return None


def test_one_broken_module_does_not_stop_the_others() -> None:
    cfg = Config(concurrency=4, cache_dir=None)
    with Engine(cfg) as engine:
        modules = [_Boom(engine.http, cfg), _Fine(engine.http, cfg), _Quiet(engine.http, cfg)]
        results = engine._run_all(modules, "example.com", TargetType.DOMAIN, None)

    by_name = {r.module: r for r in results}
    assert by_name["boom"].status is ModuleStatus.FAILED
    assert "RuntimeError: module is broken" in by_name["boom"].status_reason
    assert by_name["fine"].status is ModuleStatus.SUCCESS
    assert by_name["fine"].findings  # the healthy module still delivered
    assert by_name["quiet"].status is ModuleStatus.EMPTY


def test_a_rate_limited_source_is_reported_as_such_not_as_empty() -> None:
    res = ScanResult(module="social", target="t", target_type=TargetType.USERNAME)
    recorder = _ModuleHttp(Fetcher(concurrency=1))
    try:
        recorder._record(Response(url="u", status=429))
        recorder._record(Response(url="u", status=429))
        Engine._finalise_status(res, recorder)
    finally:
        recorder._fetcher.close()
    assert res.status is ModuleStatus.RATE_LIMITED
    assert "rate limited" in res.status_reason


def test_partial_when_some_sources_answered() -> None:
    res = ScanResult(module="subdomains", target="t", target_type=TargetType.DOMAIN)
    res.add("source: crt.sh", "12 names", source="crt.sh")
    recorder = _ModuleHttp(Fetcher(concurrency=1))
    try:
        recorder._record(Response(url="u", status=200))
        recorder._record(Response(url="u", status=403))
        Engine._finalise_status(res, recorder)
    finally:
        recorder._fetcher.close()
    assert res.status is ModuleStatus.PARTIAL


# ------------------------------------------------------------------- reports


def _investigation_with_gaps() -> Investigation:
    inv = Investigation(target="example.com", target_type=TargetType.DOMAIN)
    good = ScanResult(module="dns", target="example.com", target_type=TargetType.DOMAIN)
    good.add("A", ["1.2.3.4"], source="doh")
    good.add("guess", "Jane", source="heuristic", confidence=Confidence.POSSIBLE,
             severity=Severity.NOTABLE)
    blocked = ScanResult(module="social", target="example.com", target_type=TargetType.DOMAIN)
    blocked.degrade(ModuleStatus.RATE_LIMITED, "3 source request(s) came back 'rate limited'")
    inv.results = [good, blocked]
    inv.skipped = [("pwned", "needs $HIBP_API_KEY")]
    return inv.finish()


def test_status_rows_cover_incomplete_and_skipped() -> None:
    rows = status_rows(_investigation_with_gaps())
    assert ("pwned", "skipped", "needs $HIBP_API_KEY") in rows
    assert any(name == "social" and status == "rate limited" for name, status, _ in rows)


def test_confidence_counts() -> None:
    assert confidence_counts(_investigation_with_gaps()) == {
        "confirmed": 1, "likely": 0, "possible": 1
    }


@pytest.mark.parametrize("fmt", sorted(RENDERERS))
def test_every_renderer_shows_the_coverage_gaps(fmt: str) -> None:
    out = RENDERERS[fmt](_investigation_with_gaps())
    assert "social" in out
    assert "pwned" in out, f"{fmt} hides a skipped module"


def test_json_export_carries_status_and_no_secrets() -> None:
    payload = json.loads(RENDERERS["json"](_investigation_with_gaps()))
    assert payload["module_status"]["social"] == "rate limited"
    assert payload["skipped"] == [{"module": "pwned", "reason": "needs $HIBP_API_KEY"}]
    assert "api_keys" not in json.dumps(payload)


# ----------------------------------------------------------------- config file


def test_missing_config_is_created_with_defaults(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "config.json"
    manager = ConfigManager(path).load()
    assert path.exists()
    assert manager.get("settings.timeout") == 12.0
    assert json.loads(path.read_text("utf-8"))["settings"]["max_retries"] == 2


def test_malformed_config_falls_back_without_raising(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text("{ this is not json", "utf-8")
    manager = ConfigManager(path).load()
    assert manager.get("settings.timeout") == 12.0
    assert any("not valid JSON" in p for p in manager.problems)
    # ...and it still produces a usable Config rather than dying.
    assert manager.to_config().timeout == 12.0


def test_partial_config_keeps_every_other_default(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"settings": {"timeout": 3}}), "utf-8")
    manager = ConfigManager(path).load()
    assert manager.get("settings.timeout") == 3
    assert manager.get("settings.max_concurrent_tasks") == 24


def test_invalid_values_are_clamped_not_fatal(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"settings": {
        "timeout": "banana",
        "max_concurrent_tasks": 9999,
        "request_delay_min": 2.0,
        "request_delay_max": 0.5,
        "verify_tls": "yes please",
    }}), "utf-8")
    manager = ConfigManager(path).load()
    cfg = manager.to_config()
    assert cfg.timeout == 12.0
    assert cfg.concurrency == 128
    assert cfg.per_host_delay_max == 2.0
    assert cfg.verify_tls is True
    assert len(manager.problems) >= 4


def test_nested_get_is_safe_on_any_shape(tmp_path: Path) -> None:
    manager = ConfigManager(tmp_path / "c.json").load()
    assert manager.get("settings.timeout") == 12.0
    assert manager.get("nope.nothing.here", "fallback") == "fallback"
    assert manager.get("settings.timeout.deeper", "fallback") == "fallback"


def test_environment_beats_the_config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"api_keys": {"github": "from-file"}}), "utf-8")
    monkeypatch.setenv("GITHUB_TOKEN", "from-env")
    assert ConfigManager(path).load().resolved_keys()["github"] == "from-env"
    monkeypatch.delenv("GITHUB_TOKEN")
    assert ConfigManager(path).load().resolved_keys()["github"] == "from-file"


def test_long_form_key_names_are_accepted(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"api_keys": {"haveibeenpwned": "k", "hunter_io": "h"}}), "utf-8")
    keys = ConfigManager(path).load().resolved_keys()
    assert keys["hibp"] == "k" and keys["hunter"] == "h"


def test_unknown_key_names_are_reported_and_ignored(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"api_keys": {"nonsense": "x"}}), "utf-8")
    manager = ConfigManager(path).load()
    assert "nonsense" not in manager.resolved_keys()
    assert any("nonsense" in p for p in manager.problems)


def test_show_never_reveals_a_key(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"api_keys": {"shodan": "super-secret-value"}}), "utf-8")
    manager = ConfigManager(path).load()
    assert "super-secret-value" not in json.dumps(manager.redacted())
    assert manager.redacted()["api_keys"]["shodan"] == "set (hidden)"


def test_socks_proxy_is_refused_loudly_not_silently(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"proxies": {"enabled": True, "socks5": "127.0.0.1:9050"}}), "utf-8")
    manager = ConfigManager(path).load()
    assert manager.proxy() is None
    assert any("SOCKS" in p for p in manager.problems)


def test_modules_can_be_disabled_in_the_file(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"modules_enabled": {"dorks": False, "dns": True}}), "utf-8")
    manager = ConfigManager(path).load()
    assert manager.disabled_modules == frozenset({"dorks"})
    assert manager.module_enabled("dns") and not manager.module_enabled("dorks")
    assert manager.to_config().disabled_modules == frozenset({"dorks"})


def test_command_line_overrides_win(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"settings": {"timeout": 5}}), "utf-8")
    manager = ConfigManager(path).load()
    assert manager.to_config(timeout=None).timeout == 5      # flag not given
    assert manager.to_config(timeout=99.0).timeout == 99.0   # flag given


def test_options_bag_carries_module_switches() -> None:
    cfg = Config()
    assert cfg.option("verify_hits", "default") == "default"
    cfg.set_option("verify_hits", True)
    assert cfg.option("verify_hits") is True


# --------------------------------------------------------------------- logging


def test_logging_redacts_known_keys_and_secret_parameters(tmp_path: Path) -> None:
    log_file = tmp_path / "nova.log"
    logging_config.setup_logging(2, log_file, secrets=["super-secret-key-value"])
    log = logging_config.get_logger("test")
    log.info("querying with key super-secret-key-value")
    log.info("GET https://api.example.com/v1?apikey=abcdef123456&q=x")
    log.info("header Authorization: Bearer tok_abcdef123456")
    for handler in logging.getLogger(logging_config.LOGGER_NAME).handlers:
        handler.flush()

    written = log_file.read_text("utf-8")
    assert "super-secret-key-value" not in written
    assert "abcdef123456" not in written
    assert written.count("***") >= 3


def test_redact_is_available_without_a_logger() -> None:
    logging_config.register_secrets(["another-secret-value"])
    assert "another-secret-value" not in logging_config.redact("x another-secret-value y")


def test_a_broken_format_string_does_not_lose_the_line(tmp_path: Path) -> None:
    log_file = tmp_path / "nova.log"
    logging_config.setup_logging(2, log_file)
    logging_config.get_logger("test").info("%s and %s", "only-one-arg")
    for handler in logging.getLogger(logging_config.LOGGER_NAME).handlers:
        handler.flush()
    assert "and" in log_file.read_text("utf-8")
