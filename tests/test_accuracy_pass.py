"""The 2026-11-26 accuracy pass, one test per defect.

Each defect below was found by reading NOVA against Sherlock, Maigret,
WhatsMyName, SpiderFoot, theHarvester, subfinder, Amass and OpenOSINT, or was
seen in a real report. Every test names what went wrong, so a future change
that brings one back fails with the reason attached.
"""

from __future__ import annotations

import pytest

from nova_osint.core import sitedata
from nova_osint.core.addresses import judge_address
from nova_osint.core.config import Config
from nova_osint.core.engine import generic_handle, pivot_refusal
from nova_osint.core.http import Response
from nova_osint.core.models import (
    Confidence,
    Investigation,
    ModuleStatus,
    ScanResult,
    TargetType,
)


class FakeHttp:
    def __init__(self, routes=None, default: int = 404) -> None:
        self.routes = routes or {}
        self.default = default
        self.calls: list[str] = []

    def get(self, url: str, **kw) -> Response:
        self.calls.append(url)
        for fragment, response in self.routes.items():
            if fragment in url:
                return response(url) if callable(response) else response
        return Response(url=url, status=self.default)

    def get_json(self, url: str, default=None, **kw):
        return self.get(url, **kw).json(default)

    def map(self, fn, items):
        return [fn(i) for i in items]


def _r(body: str = "", status: int = 200, headers=None) -> Response:
    return Response(url="https://site.test/", status=status, body=body.encode(),
                    headers={"content-type": "text/html", **(headers or {})})


# ----------------------------------------------- "Name = search" in a report


def test_a_search_category_is_not_a_person_called_search():
    from nova_osint.core.biography import extract

    inv = Investigation(target="alice", target_type=TargetType.USERNAME)
    res = ScanResult(module="websearch", target="alice",
                     target_type=TargetType.USERNAME)
    res.add("search: education", "Alice went to some school - snippet",
            source="websearch")
    inv.results.append(res)
    subjects = extract(inv.finish())
    assert [s.name for s in subjects] == ["alice"]
    assert all(not a.values for s in subjects for a in s.attributes
               if a.label == "Education")


def test_a_kind_prefix_is_not_a_person_either():
    from nova_osint.core.biography import extract

    inv = Investigation(target="alice", target_type=TargetType.USERNAME)
    res = ScanResult(module="email", target="alice",
                     target_type=TargetType.USERNAME)
    res.add("verified: location", "Paris", source="gravatar")
    inv.results.append(res)
    assert [s.name for s in extract(inv.finish())] == ["alice"]


# -------------------------------------------------- the "sales" explosion


def test_a_shared_mailbox_does_not_seed_a_username_sweep():
    from nova_osint.modules.email import EmailModule

    module = EmailModule(FakeHttp(), Config())
    res = ScanResult(module="email", target="sales@shop.test",
                     target_type=TargetType.EMAIL)
    module.run("sales@shop.test", res)
    assert not [e for e in res.nodes if e.etype.value == "username"], \
        "'sales' from a shared mailbox was swept across 480 sites"


def test_the_username_module_declines_a_role_address():
    from nova_osint.modules.username import UsernameModule

    assert UsernameModule(FakeHttp(), Config()).refuses("sales@shop.test")
    assert UsernameModule(FakeHttp(), Config()).refuses("jane.doe@shop.test") is None


@pytest.mark.parametrize("handle", ["sales", "admin", "bob", "42", "info"])
def test_generic_handles_are_not_leads(handle):
    assert generic_handle(handle)
    assert pivot_refusal(handle, TargetType.USERNAME)


@pytest.mark.parametrize("handle", ["unorfl", "ada_lovelace1815", "eastdakota.com",
                                    "alice@mastodon.social"])
def test_distinctive_handles_still_are(handle):
    assert generic_handle(handle) == ""


def test_a_dmarc_report_processor_is_not_followed():
    assert judge_address("re+abc123@dmarc.postmarkapp.com").kind == "automated"
    assert judge_address("x@rua.dmarcian.com").kind == "automated"


# ------------------------------------------------ WebFinger mis-pivots


def test_webfinger_is_not_asked_about_a_domain_or_a_freemail_address():
    from nova_osint.modules.correlators import WebFingerModule

    wf = WebFingerModule(FakeHttp(), Config())
    assert wf.refuses("designsbyracquel.com")
    assert wf.refuses("someone@gmail.com")
    assert wf.refuses("noreply@example.org")
    assert wf.refuses("unorfl") is None
    assert wf.refuses("alice@hachyderm.io") is None


def test_the_engine_reports_a_refusal_as_a_named_skip():
    from nova_osint.core.engine import Engine

    with Engine(Config()) as engine:
        ttype, runnable, skipped = engine.plan("designsbyracquel.com",
                                               only=["webfinger"],
                                               target_type=TargetType.USERNAME)
    assert not runnable
    assert skipped and "fediverse" in skipped[0][1]


# --------------------------------------------- refusals are not answers


def _username(http):
    from nova_osint.modules.username import UsernameModule

    return UsernameModule(http, Config())


_MSG_SITE = {"url": "https://site.test/u/{}", "errorType": "message",
             "errorMsg": ["User not found"]}


@pytest.mark.parametrize("resp,reason", [
    (_r("slow down", 429), "rate limited"),
    (_r("<title>Just a moment...</title>", 403), "refused"),
    (_r("<title>Just a moment...</title>", 503), "server error"),
    (_r("ok", 200, {"cf-mitigated": "challenge"}), "bot challenge"),
    (_r("<html><title>Attention Required! | Cloudflare</title>", 200), "block page"),
])
def test_a_block_page_is_a_refusal_not_an_account(resp, reason):
    """A message-type site read a WAF page as a profile: the page lacks the
    site's "not found" text, so "absent" passed for "present"."""
    hit = _username(FakeHttp({"site.test": resp}))._check("Site", _MSG_SITE, "alice")
    assert hit["outcome"] == "refused" and not hit["claimed"]
    assert reason in hit["refusal"]


def test_a_documented_not_found_code_is_an_answer():
    meta = {"url": "https://site.test/u/{}", "errorType": "status_code",
            "errorCode": [403]}
    hit = _username(FakeHttp({"site.test": _r("", 403)}))._check("S", meta, "alice")
    assert hit["outcome"] == "answered" and not hit["claimed"]


def test_presence_strings_are_required_where_the_site_defines_them():
    """Maigret's rule - present AND not absent. A login wall has no "not
    found" text either, so absence alone is not an account."""
    meta = {**_MSG_SITE, "presenseStrs": ['"profile_id"']}
    wall = _username(FakeHttp({"site.test": _r("<h1>Log in</h1>")}))
    assert not wall._check("S", meta, "alice")["claimed"]
    real = _username(FakeHttp({"site.test": _r('{"profile_id": 7, "u": "alice"}')}))
    hit = real._check("S", meta, "alice")
    assert hit["claimed"] and hit["positive"]


def test_a_sites_own_error_markers_mean_refused():
    meta = {**_MSG_SITE, "errors": {"Please wait a few minutes": "rate limited"}}
    hit = _username(FakeHttp({"site.test": _r("Please wait a few minutes")}))._check(
        "S", meta, "alice")
    assert hit["outcome"] == "refused"


def test_a_verified_hit_without_positive_evidence_is_only_likely():
    mod = _username(FakeHttp())
    hit = {"site": "S", "url": "u", "outcome": "answered", "claimed": True,
           "status": 200, "confidence": Confidence.LIKELY, "positive": False,
           "meta": {"url": "https://s.test/{}", "errorType": "status_code"}}
    mod._check = lambda site, meta, handle: {"outcome": "answered", "claimed": False}
    kept = mod._verify([hit], {})
    assert kept[0]["verified"] is True
    assert kept[0]["confidence"] is Confidence.LIKELY


# ----------------------------------------------- the site catalogue


_MAIGRET = {
    "engines": {"Forum": {"site": {"checkType": "message",
                                   "absenceStrs": ["no such member"],
                                   "presenseStrs": ["member-card"],
                                   "url": "{urlMain}/members/{username}"}}},
    "sites": {
        "BigForum": {"engine": "Forum", "urlMain": "https://bigforum.test",
                     "alexaRank": 900},
        "Dead": {"url": "https://dead.test/{username}", "checkType": "status_code",
                 "alexaRank": 10, "disabled": True},
        "Tail": {"url": "https://tail.test/{username}", "checkType": "status_code",
                 "alexaRank": 0},
        "Strict": {"url": "https://strict.test/{username}", "checkType": "message",
                   "absenceStrs": ["gone"], "presenseStrs": ["data-user"],
                   "alexaRank": 50, "ignore403": True},
    },
}


def test_maigret_engines_disabled_sites_and_the_long_tail():
    conv = sitedata.convert_maigret(_MAIGRET)
    assert set(conv) == {"BigForum", "Strict"}
    forum = conv["BigForum"]
    assert forum["url"] == "https://bigforum.test/members/{}"
    assert forum["errorType"] == "message"
    assert forum["presenseStrs"] == ["member-card"]
    assert conv["Strict"]["errorCode"] == [403]


def test_merge_prefers_positive_evidence_and_honours_sherlocks_exclusions():
    sherlock = {
        "Strict": {"url": "https://www.strict.test/{}", "errorType": "message",
                   "errorMsg": ["gone"]},
        "Flaky": {"url": "https://flaky.test/{}", "errorType": "status_code"},
        "Plain": {"url": "https://plain.test/{}", "errorType": "status_code"},
    }
    merged, n = sitedata.merge(sherlock, sitedata.convert_maigret(_MAIGRET),
                               excluded={"Flaky"})
    assert merged["Strict"]["source"] == "maigret"
    assert "Flaky" not in merged
    assert merged["Plain"]["source"] == "sherlock"
    assert "BigForum" in merged
    assert n == {"sherlock": 1, "maigret": 1, "upgraded": 1, "excluded": 1}


# ------------------------------------------------------- subdomains


def test_the_host_normaliser():
    from nova_osint.modules.domain import normalise_host

    assert normalise_host("*.Foo.Example.com.", "example.com") == "foo.example.com"
    assert normalise_host("m.testexample.com", "example.com") == ""
    assert normalise_host("10.0.0.1", "example.com") == ""
    assert normalise_host("bad_label!.example.com", "example.com") == ""
    assert normalise_host("_dmarc.example.com", "example.com") == "_dmarc.example.com"


def _dns_answer(ip: str) -> Response:
    import json

    body = json.dumps({"Status": 0, "Answer": [{"type": 1, "data": ip}]})
    return Response(url="dns", status=200, body=body.encode(),
                    headers={"content-type": "application/dns-json"})


def test_wildcard_dns_does_not_make_every_name_live(monkeypatch):
    """With ``*.example.com`` in DNS every name resolves, and every stale
    certificate name used to be reported as a live host."""
    from nova_osint.modules import domain as dmod

    def answers(self, host):
        if host == "real.example.com":
            return frozenset({"198.51.100.7"})
        return frozenset({"203.0.113.1"})  # the wildcard answers everything else

    monkeypatch.setattr(dmod.SubdomainModule, "_answers", answers)
    for src in ("crtsh", "certspotter", "crtname", "shodanct", "thc", "anubis",
                "hackertarget", "rapiddns", "urlscan"):
        monkeypatch.setattr(dmod.SubdomainModule, "_" + src,
                            lambda self, d: ("ok", {"real.example.com",
                                                    "stale.example.com"}))
    mod = dmod.SubdomainModule(FakeHttp(), Config())
    res = ScanResult(module="subdomains", target="example.com",
                     target_type=TargetType.DOMAIN)
    mod.run("example.com", res)
    by = {f.label: f.value for f in res.findings}
    assert by["live subdomains"] == ["real.example.com"]
    assert by["resolve only through the wildcard"] == ["stale.example.com"]


def test_a_failed_source_is_not_an_empty_one(monkeypatch):
    from nova_osint.modules import domain as dmod

    mod = dmod.SubdomainModule(FakeHttp({"crt.sh": _r("bad gateway", 502)}), Config())
    state, found = mod._safe(mod._crtsh, "example.com")
    assert state.startswith("failed") and not found
    over = dmod.SubdomainModule(FakeHttp({"hackertarget": _r("API count exceeded")}),
                                Config())
    assert over._safe(over._hackertarget, "example.com")[0] == "limited"


# ------------------------------------------------------ report hygiene


def test_one_module_failing_on_several_pivots_is_one_line_naming_them():
    from nova_osint.core.analyst import _coverage
    from nova_osint.core.report import status_rows

    inv = Investigation(target="seed", target_type=TargetType.USERNAME)
    for t in ("seed", "b", "c"):
        r = ScanResult(module="username", target=t, target_type=TargetType.USERNAME)
        r.degrade(ModuleStatus.PARTIAL, "time limit")
        r.status = ModuleStatus.UNAVAILABLE
        inv.results.append(r)
    inv.skipped += [("webfinger", "x"), ("webfinger", "x")]
    lines = _coverage(inv.finish())
    assert len(lines) == 1 and "3 targets" in lines[0]
    rows = status_rows(inv)
    assert len([r for r in rows if r[0] == "webfinger"]) == 1
    assert {r[0] for r in rows} >= {"username", "username (b)", "username (c)"}


def test_output_path_accepts_a_string():
    from pathlib import Path

    from nova_osint.cli import _resolve_output

    cfg = Config()
    assert _resolve_output("sub/x.json", cfg) == Path("sub/x.json")
    assert _resolve_output("x.json", cfg).name == "x.json"


# --------------------------------------- CDN edge addresses are not leads


@pytest.mark.parametrize("ip,owner", [("104.21.10.105", "Cloudflare"),
                                      ("2606:4700:3034::ac43:835a", "Cloudflare"),
                                      ("216.150.1.193", "Vercel"),
                                      ("8.8.8.8", "")])
def test_shared_edges_are_recognised(ip, owner):
    from nova_osint.core.infra import shared_edge

    assert shared_edge(ip) == owner
    assert bool(pivot_refusal(ip, TargetType.IP)) is bool(owner)


def test_cotenants_on_a_cdn_address_do_not_become_the_targets_domains():
    """On a Cloudflare-fronted site, Shodan's list of names seen on the edge
    address became "hosted-name" entities at reverse-DNS weight, and two
    unrelated domains were investigated as the target's."""
    import json

    from nova_osint.modules.ip import IpModule

    ipapi = json.dumps({"status": "success", "as": "AS13335 Cloudflare, Inc.",
                        "org": "Cloudflare, Inc.", "isp": "Cloudflare, Inc."})
    idb = json.dumps({"ip": "104.21.10.105", "hostnames": ["stranger.example",
                                                           "other.example"]})
    http = FakeHttp({"ip-api.com": _r(ipapi), "internetdb.shodan.io": _r(idb)})
    res = ScanResult(module="ip", target="104.21.10.105", target_type=TargetType.IP)
    IpModule(http, Config()).run("104.21.10.105", res)
    assert not [e for e in res.nodes if e.etype.value in ("domain", "host")]
    assert any(f.label == "shared infrastructure" for f in res.findings)


@pytest.fixture
def registry_of():
    from nova_osint.core import registry

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


def test_a_refused_lead_is_not_reported_as_expanded(registry_of):
    """The walk listed every dequeued lead under "expanded", including ones
    the gate refused - so a Cloudflare edge read as investigated."""
    from nova_osint.core.engine import Engine
    from nova_osint.core.entities import EntityType
    from nova_osint.core.registry import Module

    class DomainToIp(Module):
        name = "fake-dns"
        accepts = frozenset({TargetType.DOMAIN})

        def run(self, target, result):
            result.entity(EntityType.IP, "104.21.10.105", relation="resolves-to",
                          evidence="dns-a")

    class IpLeaf(Module):
        name = "fake-ip"
        accepts = frozenset({TargetType.IP})

        def run(self, target, result):
            result.add("x", "y", source="t")

    registry_of(DomainToIp, IpLeaf)
    with Engine(Config(concurrency=4, cache_dir=None)) as e:
        inv = e.investigate("example.com")
    assert "ip:104.21.10.105" not in inv.expansion.expanded
    assert any("104.21.10.105" in lead for lead, _ in inv.not_followed)
    assert not any(r.module == "fake-ip" for r in inv.results)


def test_wildcard_certificates_are_still_reported(monkeypatch):
    """The normaliser strips ``*.``; the wildcard-certificate line it used to
    feed must survive that."""
    from nova_osint.modules import domain as dmod

    for src in ("crtsh", "certspotter", "crtname", "shodanct", "thc", "anubis",
                "hackertarget", "rapiddns", "urlscan"):
        monkeypatch.setattr(dmod.SubdomainModule, "_" + src,
                            lambda self, d: ("ok", {"*.example.com", "a.example.com"}))
    cfg = Config()
    cfg.passive_only = True
    res = ScanResult(module="subdomains", target="example.com",
                     target_type=TargetType.DOMAIN)
    dmod.SubdomainModule(FakeHttp(), cfg).run("example.com", res)
    by = {f.label: f.value for f in res.findings}
    assert by["wildcard certificates"] == ["*.example.com"]
    assert by["subdomains (unresolved)"] == ["a.example.com"]


@pytest.mark.parametrize("host", ["gmail.com", "google.com", "outlook.com"])
def test_a_freemail_providers_domain_is_not_the_subjects(host):
    """Following someone@gmail.com to its domain ran every domain module on
    gmail.com, and then on Google's DMARC report robot."""
    assert pivot_refusal(host, TargetType.DOMAIN)


def test_google_dmarc_report_sink_is_automated():
    assert judge_address("mailauth-reports@google.com").kind == "automated"
    assert pivot_refusal("designsbyracquel.com", TargetType.DOMAIN) == ""
