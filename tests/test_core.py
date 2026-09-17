"""Offline tests. Nothing here touches the network.

Anything that needs the live internet is marked ``network`` and skipped by
default, so ``pytest`` stays fast and deterministic in CI.
"""

from __future__ import annotations

import io
import json
import re
from pathlib import Path

import pytest

from nova_osint.core import dns as dnsmod
from nova_osint.core import report
from nova_osint.core.config import Config, load_env_file
from nova_osint.core.http import Fetcher, Response, hostname_of
from nova_osint.core.models import (
    Confidence,
    Investigation,
    ScanResult,
    Severity,
    TargetType,
)
from nova_osint.core.registry import all_modules, detect_type, select
from nova_osint.modules import dorks as dorks_mod
from nova_osint.modules import email as email_mod
from nova_osint.modules import web as web_mod


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


# ----------------------------------------------------------------- detection


@pytest.mark.parametrize(
    "value,expected",
    [
        ("example.com", TargetType.DOMAIN),
        ("sub.example.co.uk", TargetType.DOMAIN),
        ("alice@example.com", TargetType.EMAIL),
        ("8.8.8.8", TargetType.IP),
        ("2001:4860:4860::8888", TargetType.IP),
        ("+1 415 555 2671", TargetType.PHONE),
        ("+442079460958", TargetType.PHONE),
        ("octocat", TargetType.USERNAME),
        ("some.user_name-1", TargetType.USERNAME),
        ("https://example.com/path", TargetType.URL),
        ("", TargetType.UNKNOWN),
        ("what is this??", TargetType.UNKNOWN),
    ],
)
def test_detect_type(value: str, expected: TargetType) -> None:
    assert detect_type(value) is expected


def test_phone_not_mistaken_for_username() -> None:
    # A bare 10-digit run is a phone number, not a handle.
    assert detect_type("4155552671") is TargetType.PHONE
    # ...but a short numeric handle is not.
    assert detect_type("user123") is TargetType.USERNAME


def test_hostname_of() -> None:
    assert hostname_of("example.com") == "example.com"
    assert hostname_of("https://user@example.com:8443/x?y=1") == "example.com"


# -------------------------------------------------------------------- registry


def test_every_module_declares_itself() -> None:
    for cls in all_modules():
        assert cls.name and cls.name.islower(), cls
        assert cls.description, cls
        assert cls.accepts, f"{cls.name} accepts nothing"


def test_every_target_type_has_a_module() -> None:
    for ttype in TargetType:
        if ttype is TargetType.UNKNOWN:
            continue
        assert select(ttype), f"nothing handles {ttype}"


def test_select_rejects_unknown_module() -> None:
    with pytest.raises(ValueError, match="unknown module"):
        select(TargetType.DOMAIN, only=["no-such-module"])


def test_select_exclude() -> None:
    names = {c.name for c in select(TargetType.DOMAIN, exclude=["dorks"])}
    assert "dorks" not in names
    assert "dns" in names


def test_key_gated_module_is_skipped_without_a_key() -> None:
    cfg = Config()  # no keys
    fetch = Fetcher(concurrency=1)
    try:
        cls = next(c for c in all_modules() if c.requires_key)
        inst = cls(fetch, cfg)
        assert not inst.enabled
        assert "needs $" in (inst.skip_reason() or "")
    finally:
        fetch.close()


def test_passive_mode_disables_active_modules() -> None:
    cfg = Config(passive_only=True)
    fetch = Fetcher(concurrency=1)
    try:
        for cls in all_modules():
            inst = cls(fetch, cfg)
            if cls.active:
                assert not inst.enabled, f"{cls.name} ran in passive mode"
    finally:
        fetch.close()


# ----------------------------------------------------------------------- dns


@pytest.mark.parametrize(
    "raw,expected",
    [
        ('"simple"', "simple"),
        ("1.2.3.4", "1.2.3.4"),
        ('"v=spf1 a" "b ~all"', "v=spf1 a" + "b ~all"),
        ('"part1" "part2" "part3"', "part1part2part3"),
    ],
)
def test_txt_chunks_are_concatenated(raw: str, expected: str) -> None:
    # A >255-byte TXT record arrives split into character strings; joining them
    # naively with the quotes left in breaks SPF and DMARC parsing.
    assert dnsmod._rdata(raw) == expected


# ---------------------------------------------------------------------- http


def test_response_helpers() -> None:
    r = Response(url="u", status=200, headers={"content-type": "application/json"},
                 body=b'{"a": 1}')
    assert r.ok
    assert r.json() == {"a": 1}
    assert r.header("Content-Type") == "application/json"
    assert Response(url="u", status=0, error="boom").ok is False
    assert Response(url="u", status=500).json("fallback") == "fallback"


def test_cache_roundtrip(tmp_path: Path) -> None:
    from nova_osint.core.http import _Cache

    cache = _Cache(tmp_path, ttl=60)
    resp = Response(url="u", status=200, headers={"x": "y"}, body=b"hello")
    cache.put("k", resp)
    hit = cache.get("k")
    assert hit is not None and hit.body == b"hello" and hit.from_cache


def test_cache_ignores_transport_failures(tmp_path: Path) -> None:
    from nova_osint.core.http import _Cache

    cache = _Cache(tmp_path, ttl=60)
    cache.put("k", Response(url="u", status=0, error="timeout"))
    assert cache.get("k") is None


def test_map_survives_a_raising_worker() -> None:
    fetch = Fetcher(concurrency=4)
    try:
        def boom(i: int) -> int:
            if i == 2:
                raise RuntimeError("nope")
            return i * 10

        assert fetch.map(boom, [1, 2, 3]) == [10, None, 30]
    finally:
        fetch.close()


# -------------------------------------------------------------------- models


def _sample() -> Investigation:
    inv = Investigation(target="example.com", target_type=TargetType.DOMAIN)
    res = ScanResult(module="dns", target="example.com", target_type=TargetType.DOMAIN)
    res.add("A", ["1.2.3.4"], source="doh")
    res.add("SPF", "missing", source="doh", severity=Severity.HIGH)
    res.add("guess", "maybe", source="x", confidence=Confidence.POSSIBLE,
            url="https://example.com")
    res.pivot("1.2.3.4", TargetType.IP, "A record")
    res.pivot("1.2.3.4", TargetType.IP, "duplicate")
    res.error("something was flaky")
    inv.results.append(res)
    return inv


def test_pivots_are_deduplicated() -> None:
    assert len(_sample().pivots) == 1


def test_investigation_serialises() -> None:
    payload = json.loads(json.dumps(_sample().to_dict()))
    assert payload["summary"] == {
        "modules_run": 1, "findings": 3, "pivots": 1, "errors": 1,
        "incomplete": 0, "skipped": 0,
    }
    assert payload["results"][0]["findings"][1]["severity"] == "high"


# -------------------------------------------------------------------- reports


@pytest.mark.parametrize("fmt", sorted(report.RENDERERS))
def test_every_renderer_produces_output(fmt: str) -> None:
    out = report.RENDERERS[fmt](_sample())
    assert isinstance(out, str) and out.strip()
    assert "example.com" in out


def test_html_escapes_untrusted_values() -> None:
    inv = _sample()
    inv.results[0].add("title", "<script>alert(1)</script>", source="http")
    html = report.render_html(inv)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_min_severity_filters_console_output() -> None:
    high_only = report.render_console(_sample(), min_severity=Severity.HIGH)
    assert "SPF" in high_only
    assert "guess" not in high_only


def test_csv_has_one_row_per_finding() -> None:
    lines = [line for line in report.render_csv(_sample()).splitlines() if line.strip()]
    assert len(lines) == 4  # header + 3 findings


def test_write_infers_format_from_suffix(tmp_path: Path) -> None:
    path = report.write(_sample(), tmp_path / "out.md")
    assert path.read_text("utf-8").startswith("# OSINT report")


# -------------------------------------------------------------------- modules


def test_favicon_hash_matches_known_murmur3() -> None:
    # Reference vectors for MurmurHash3 x86 32-bit.
    assert web_mod._murmur3_32(b"") == 0
    assert web_mod._murmur3_32(b"hello") == 613153351


def test_guess_name_from_email_local_part() -> None:
    assert email_mod._guess_name("jane.doe") == "Jane Doe"
    assert email_mod._guess_name("jane_doe99") == "Jane Doe"
    assert email_mod._guess_name("jdoe") is None


def test_handle_candidates() -> None:
    out = email_mod._handle_candidates("jane.doe99")
    assert "jane.doe99" in out and "janedoe99" in out


def test_dorks_build_valid_urls() -> None:
    cfg = Config()
    fetch = Fetcher(concurrency=1)
    try:
        res = ScanResult(module="dorks", target="example.com", target_type=TargetType.DOMAIN)
        dorks_mod.DorksModule(fetch, cfg).run("example.com", res)
        assert len(res.findings) > 10
        for f in res.findings:
            assert f.url and f.url.startswith("https://")
            assert " " not in f.url  # every query must be percent-encoded
    finally:
        fetch.close()


def test_phone_module_without_library(monkeypatch: pytest.MonkeyPatch) -> None:
    from nova_osint.modules import phone as phone_mod

    monkeypatch.setattr(phone_mod, "HAVE_PN", False)
    res = ScanResult(module="phone", target="+442079460958", target_type=TargetType.PHONE)
    fetch = Fetcher(concurrency=1)
    try:
        phone_mod.PhoneModule(fetch, Config()).run("+442079460958", res)
    finally:
        fetch.close()
    values = " ".join(str(f.value) for f in res.findings)
    assert "United Kingdom" in values  # fallback still identifies the country


# --------------------------------------------------------------------- config


def test_env_file_loading(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = tmp_path / ".env"
    f.write_text("# comment\nSHODAN_API_KEY='abc123'\nEMPTY=\nJUNK\n", "utf-8")
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    assert load_env_file(f) == 1
    assert Config.from_env().key("shodan") == "abc123"


def test_config_never_exposes_missing_keys() -> None:
    cfg = Config()
    assert cfg.key("shodan") is None
    assert cfg.has("shodan") is False


def test_orbit_scene_fits_a_standard_terminal() -> None:
    from nova_osint.core import art

    lines = [_strip_ansi(line) for line in art.still(0.4).splitlines()]
    assert len(lines) == art.OrbitScene().h
    assert max(len(line) for line in lines) <= 80


def test_planets_move_and_the_sun_does_not() -> None:
    from nova_osint.core import art

    scene = art.OrbitScene()

    def positions(t: float) -> dict[str, tuple[int, int]]:
        out: dict[str, tuple[int, int]] = {}
        for y, row in enumerate(scene.frame(t)):
            for x, (ch, _) in enumerate(row):
                if ch in "◦○◉●✦☀":
                    out.setdefault(ch, (x, y))
        return out

    a, b = positions(0.0), positions(1.0)
    assert a["☀"] == b["☀"]
    assert all(a[p] != b[p] for p in "◦○◉●✦")


def test_every_art_block_renders() -> None:
    from nova_osint.core import art

    assert _strip_ansi(art.banner()).strip()
    assert "by uno" in _strip_ansi(art.banner())
    for name in art.SECTIONS:
        assert _strip_ansi(art.section(name)).strip()
    assert art.section("nonexistent") == ""
    assert art.glyph("dns") and art.glyph("not-a-module") == "•"


def test_animate_is_a_noop_off_a_terminal() -> None:
    from nova_osint.core import art

    class NotATty(io.StringIO):
        def isatty(self) -> bool:
            return False

    sink = NotATty()
    art.animate(sink, seconds=5)
    assert sink.getvalue() == ""


def test_bundled_site_list_is_wellformed() -> None:
    from nova_osint.modules.username import CORE_SITES, _clean

    sites = _clean(json.loads(CORE_SITES.read_text("utf-8")))
    assert len(sites) >= 50
    for name, meta in sites.items():
        # The handle placeholder lives in the URL for most sites, but a few
        # (Discord) POST it in a JSON body instead, so check all three slots.
        slots = f"{meta['url']}{meta.get('urlProbe', '')}{meta.get('request_payload', '')}"
        assert "{}" in slots, name
        assert meta["errorType"] in {"status_code", "message", "response_url"}, name


# ---------------------------------------------------------------------------
# no value a user can type may stop a request being made
# ---------------------------------------------------------------------------


def test_requote_escapes_what_cannot_travel_on_the_wire() -> None:
    """A space in a target used to raise InvalidURL before a byte was sent.

    Eight modules then reported that as their own failure, and the username
    sweep announced 405 sites "unreachable" without having asked one of them.
    """
    from nova_osint.core.http import requote

    assert requote("https://github.com/Ryan Rafael.keys") == (
        "https://github.com/Ryan%20Rafael.keys")
    assert requote("https://npm.example/-/v1/search?text=maintainer:A B&size=2") == (
        "https://npm.example/-/v1/search?text=maintainer:A%20B&size=2")


def test_requote_is_idempotent_so_encoded_urls_survive() -> None:
    from nova_osint.core.http import requote

    once = requote("https://api.github.com/users/a%20b")
    assert once == "https://api.github.com/users/a%20b"
    assert requote(once) == once


def test_requote_leaves_the_host_alone() -> None:
    """A non-ASCII host needs IDNA, not percent-encoding.

    Escaping it would turn a valid internationalised domain into a lookup that
    cannot succeed, which is worse than the crash it was meant to prevent.
    """
    from nova_osint.core.http import requote

    assert requote("https://xn--bcher-kva.example/p") == (
        "https://xn--bcher-kva.example/p")


def test_a_target_that_cannot_be_its_forced_type_is_refused_not_attempted() -> None:
    """--type username on a name with a space must skip, not crash eight modules."""
    from nova_osint.core.registry import shape_problem

    problem = shape_problem("Ryan Rafael", TargetType.USERNAME)
    assert problem is not None
    assert "person" in problem  # and it says what the value does look like
    assert shape_problem("ryanrafael", TargetType.USERNAME) is None
    # Types whose values are messy by nature are left alone.
    assert shape_problem("Ryan Rafael", TargetType.PERSON) is None


def test_the_banner_version_matches_the_package() -> None:
    """The splash said v1.0.0 for the whole of 1.1.0 - the number a user quotes."""
    import nova_osint
    from nova_osint.core import art

    assert nova_osint.__version__ == art.VERSION


def test_the_target_is_never_its_own_pivot() -> None:
    """A domain is a SAN on its own certificate, and --pivot follows this list."""
    inv = Investigation(target="example.com", target_type=TargetType.DOMAIN)
    res = ScanResult(module="vt", target="example.com",
                     target_type=TargetType.DOMAIN)
    res.pivot("example.com", TargetType.DOMAIN, "SAN on the TLS certificate")
    res.pivot("mail.example.com", TargetType.DOMAIN, "SAN on the TLS certificate")
    inv.results = [res]
    assert [p.target for p in inv.pivots] == ["mail.example.com"]
