"""Offline tests for the VirusTotal and SecurityTrails modules.

Neither service is contacted. Each test hands the module a fake fetcher that
replays a saved payload, which is the only honest way to test a parser: a live
call proves the network works, not that the code reads the answer correctly.
"""

from __future__ import annotations

import json

import pytest

from nova_osint.core.config import KEY_ENV, KEY_INFO, Config, key_info
from nova_osint.core.http import Response, _has_auth
from nova_osint.core.models import ModuleStatus, ScanResult, Severity, TargetType
from nova_osint.core.registry import all_modules, get_module
from nova_osint.modules.securitytrails import SecurityTrailsModule
from nova_osint.modules.virustotal import VirusTotalModule


class FakeHttp:
    """Returns a canned response per URL fragment, and records what was asked."""

    def __init__(self, routes: dict[str, Response]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, dict]] = []

    def get(self, url: str, **kw) -> Response:
        self.calls.append((url, kw.get("headers") or {}))
        for fragment, response in self.routes.items():
            if fragment in url:
                return response
        return Response(url=url, status=404)

    def get_json(self, url: str, default=None, **kw):
        return self.get(url, **kw).json(default)

    def map(self, fn, items):
        return [fn(i) for i in items]


def _json_response(payload: dict, status: int = 200) -> Response:
    return Response(url="https://example.test", status=status,
                    headers={"content-type": "application/json"},
                    body=json.dumps(payload).encode())


def _run(module_cls, http: FakeHttp, target: str, ttype: TargetType,
         **options) -> ScanResult:
    cfg = Config(keys={"virustotal": "vt-key", "securitytrails": "st-key"},
                 options=options)
    result = ScanResult(module=module_cls.name, target=target, target_type=ttype)
    module_cls(http, cfg).run(target, result)  # type: ignore[arg-type]
    return result


def _find(result: ScanResult, label: str):
    return next((f for f in result.findings if f.label == label), None)


# ------------------------------------------------------------------ key wiring


def test_every_documented_key_is_a_real_env_var() -> None:
    assert set(KEY_INFO) <= set(KEY_ENV)


def test_key_info_module_names_exist() -> None:
    """Guards the docs against drift: a renamed module must update KEY_INFO."""
    names = {cls.name for cls in all_modules()}
    for key, info in KEY_INFO.items():
        for module in info["modules"]:
            assert module in names, f"KEY_INFO[{key!r}] names a module that does not exist"


def test_keys_nothing_reads_are_labelled_as_such() -> None:
    # If a module starts using one of these, its KEY_INFO entry must be updated
    # too - otherwise the settings window keeps telling people it does nothing.
    for key in ("shodan", "hunter", "numverify", "emailrep"):
        assert key_info(key)["modules"] == ()
        assert "nothing yet" in key_info(key)["unlocks"].lower()


def test_both_new_modules_are_registered_and_key_gated() -> None:
    for name, key in (("virustotal", "virustotal"), ("securitytrails", "securitytrails")):
        cls = get_module(name)
        assert cls is not None, f"{name} is not registered"
        assert cls.requires_key == key
        assert not cls.active, f"{name} must not be marked active - it queries a third party"
        assert not cls(None, Config()).enabled  # type: ignore[arg-type]


def test_service_specific_auth_headers_defeat_the_cache() -> None:
    # VirusTotal spells it x-apikey, SecurityTrails APIKEY. Both must be seen
    # as credentials or their responses get written to the shared disk cache.
    assert _has_auth({"x-apikey": "k"})
    assert _has_auth({"APIKEY": "k"})


# ------------------------------------------------------------------ virustotal


VT_DOMAIN = {
    "data": {
        "id": "example.com",
        "attributes": {
            "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 60,
                                    "undetected": 7, "timeout": 0},
            "last_analysis_results": {
                "Fortinet": {"category": "malicious", "result": "phishing"},
                "Sophos": {"category": "suspicious", "result": "suspicious site"},
                "Google Safebrowsing": {"category": "harmless", "result": "clean"},
            },
            "categories": {"Forcepoint": "information technology", "BitDefender": "computers"},
            "popularity_ranks": {"Cisco Umbrella": {"rank": 4821},
                                 "Majestic": {"rank": 9100}},
            "reputation": -17,
            "total_votes": {"harmless": 3, "malicious": 12},
            "registrar": "RESERVED-IANA",
            "creation_date": 808372800,
            "jarm": "29d3fd00029d29d00042d43d00041d",
            "tags": ["dga"],
            "last_https_certificate": {
                "subject": {"CN": "example.com"},
                "issuer": {"O": "DigiCert Inc"},
                "extensions": {"subject_alternative_name": ["example.com", "www.example.com"]},
            },
        },
    }
}

VT_RESOLUTIONS = {
    "data": [
        {"attributes": {"ip_address": "93.184.216.34", "date": 1700000000}},
        {"attributes": {"ip_address": "93.184.216.34", "date": 1690000000}},
        {"attributes": {"ip_address": "203.0.113.9", "date": 1680000000}},
    ]
}


def test_virustotal_reports_the_verdict_and_names_the_vendors() -> None:
    http = FakeHttp({"/resolutions": _json_response(VT_RESOLUTIONS),
                     "/domains/example.com": _json_response(VT_DOMAIN)})
    res = _run(VirusTotalModule, http, "example.com", TargetType.DOMAIN)

    verdict = _find(res, "blocklist verdict")
    assert verdict is not None
    assert "2 malicious, 1 suspicious of 70 engines" in verdict.value
    assert verdict.severity is Severity.HIGH
    # The caveat travels with the finding, not just the docs.
    assert "noise" in verdict.extra["note"]

    flagged = _find(res, "flagged by")
    assert flagged is not None
    assert "Fortinet: phishing" in flagged.value
    assert not any("Safebrowsing" in v for v in flagged.value)


def test_virustotal_extracts_context_and_pivots() -> None:
    http = FakeHttp({"/resolutions": _json_response(VT_RESOLUTIONS),
                     "/domains/example.com": _json_response(VT_DOMAIN)})
    res = _run(VirusTotalModule, http, "example.com", TargetType.DOMAIN)

    assert _find(res, "content categories").value == ["computers", "information technology"]
    assert _find(res, "popularity rank").value == "#4,821 (Cisco Umbrella)"
    assert _find(res, "domain created").value == "1995-08-14"
    assert _find(res, "VirusTotal tags").value == ["dga"]
    assert "ssl.jarm" in _find(res, "JARM fingerprint").url

    historic = _find(res, "historic IPs")
    assert historic.value == ["93.184.216.34", "203.0.113.9"]  # de-duplicated, in order
    assert {p.target for p in res.pivots} >= {"93.184.216.34", "203.0.113.9"}
    assert all(p.target_type is TargetType.IP for p in res.pivots
               if p.reason == "VirusTotal passive DNS")


def test_virustotal_ip_lookup_uses_the_ip_endpoint() -> None:
    payload = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70,
                                "undetected": 4, "timeout": 0},
        "as_owner": "EDGECAST", "asn": 15133, "country": "US",
        "network": "93.184.216.0/24",
    }}}
    resolutions = {"data": [{"attributes": {"host_name": "example.com"}}]}
    http = FakeHttp({"/resolutions": _json_response(resolutions),
                     "/ip_addresses/": _json_response(payload)})
    res = _run(VirusTotalModule, http, "93.184.216.34", TargetType.IP)

    assert any("/ip_addresses/" in url for url, _ in http.calls)
    assert _find(res, "AS owner").value == "EDGECAST"
    assert _find(res, "blocklist verdict").severity is Severity.INFO
    co = _find(res, "co-hosted domains")
    assert co.value == ["example.com"]
    assert any(p.target_type is TargetType.DOMAIN for p in res.pivots)


@pytest.mark.parametrize(
    "status,expected_status,needle",
    [
        (401, ModuleStatus.BLOCKED, "rejected the API key"),
        (429, ModuleStatus.RATE_LIMITED, "quota"),
    ],
)
def test_virustotal_names_its_refusals(status, expected_status, needle) -> None:
    http = FakeHttp({"/domains/": Response(url="u", status=status)})
    res = _run(VirusTotalModule, http, "example.com", TargetType.DOMAIN)
    assert res.status is expected_status
    assert needle in res.status_reason
    assert res.errors


def test_virustotal_404_is_an_answer_not_a_failure() -> None:
    http = FakeHttp({"/domains/": Response(url="u", status=404)})
    res = _run(VirusTotalModule, http, "nope.example", TargetType.DOMAIN)
    assert res.status is ModuleStatus.SUCCESS
    assert not res.errors
    assert "no entry" in _find(res, "VirusTotal record").value


def test_virustotal_sends_the_key_as_a_header_only() -> None:
    http = FakeHttp({"/domains/": _json_response(VT_DOMAIN),
                     "/resolutions": _json_response({"data": []})})
    _run(VirusTotalModule, http, "example.com", TargetType.DOMAIN)
    for url, headers in http.calls:
        assert "vt-key" not in url, "the key must never travel in a query string"
        assert headers.get("x-apikey") == "vt-key"


# -------------------------------------------------------------- securitytrails


ST_DOMAIN = {
    "apex_domain": "example.com",
    "subdomain_count": 128,
    "alexa_rank": 15342,
    "current_dns": {
        "a": {"first_seen": "2016-02-11",
              "values": [{"ip": "93.184.216.34", "ip_organization": "Edgecast Inc."}]},
        "mx": {"values": [{"host": "mail.example.com", "priority": 10}]},
        "ns": {"values": [{"nameserver": "a.iana-servers.net"}]},
    },
}

ST_SUBDOMAINS = {"subdomains": ["www", "dev", "mail"]}

ST_WHOIS = {"result": {"items": [
    {"createdDate": "2019-04-02T00:00:00Z",
     "contact": [{"name": "Jane Doe", "email": "jane@example.com",
                  "organization": "Example Ltd"}]},
    {"createdDate": "1995-08-14T00:00:00Z",
     "contact": [{"name": "Jane Doe", "email": "admin@example.com"}]},
]}}


def test_securitytrails_basic_depth_spends_one_query() -> None:
    http = FakeHttp({"/domain/example.com": _json_response(ST_DOMAIN)})
    res = _run(SecurityTrailsModule, http, "example.com", TargetType.DOMAIN)

    assert len(http.calls) == 1, "basic depth must not touch the history endpoints"
    assert _find(res, "queries spent").value == "1"
    assert _find(res, "apex domain").value == "example.com"
    assert _find(res, "subdomains known").value == 128
    assert _find(res, "traffic rank").value == "#15,342"
    # The opt-in is advertised rather than silently costing the user's quota.
    assert "securitytrails_depth" in _find(res, "history not queried").value


def test_securitytrails_current_dns_carries_the_owner() -> None:
    http = FakeHttp({"/domain/example.com": _json_response(ST_DOMAIN)})
    res = _run(SecurityTrailsModule, http, "example.com", TargetType.DOMAIN)

    assert _find(res, "A (with owner)").value == ["93.184.216.34 (Edgecast Inc.)"]
    assert _find(res, "MX (with owner)").value == ["mail.example.com"]
    assert _find(res, "A first seen").value == "2016-02-11"
    assert any(p.target == "93.184.216.34" and p.target_type is TargetType.IP
               for p in res.pivots)


def test_securitytrails_full_depth_pulls_history() -> None:
    http = FakeHttp({
        "/domain/example.com/subdomains": _json_response(ST_SUBDOMAINS),
        "/history/example.com/whois": _json_response(ST_WHOIS),
        "/domain/example.com": _json_response(ST_DOMAIN),
    })
    res = _run(SecurityTrailsModule, http, "example.com", TargetType.DOMAIN,
               securitytrails_depth="full")

    assert len(http.calls) == 3
    assert _find(res, "queries spent").value == "3"
    subs = _find(res, "subdomains (historical)")
    assert subs.value == ["dev.example.com", "mail.example.com", "www.example.com"]

    names = _find(res, "historic registrant name")
    emails = _find(res, "historic registrant email")
    assert names.value == ["Jane Doe"]                       # de-duplicated
    assert emails.value == ["jane@example.com", "admin@example.com"]
    assert names.severity is Severity.HIGH
    assert "privacy services" in names.extra["note"]
    assert {p.target for p in res.pivots} >= {"jane@example.com", "admin@example.com"}
    assert _find(res, "earliest archived registration").value == "1995-08-14"


def test_securitytrails_quota_exhaustion_is_named() -> None:
    http = FakeHttp({"/domain/": Response(url="u", status=429)})
    res = _run(SecurityTrailsModule, http, "example.com", TargetType.DOMAIN)
    assert res.status is ModuleStatus.RATE_LIMITED
    assert "quota" in res.status_reason
    assert "quota exhausted" in res.errors[0]


def test_securitytrails_bad_key_is_named() -> None:
    http = FakeHttp({"/domain/": Response(url="u", status=403)})
    res = _run(SecurityTrailsModule, http, "example.com", TargetType.DOMAIN)
    assert res.status is ModuleStatus.BLOCKED
    assert "SECURITYTRAILS_API_KEY" in res.errors[0]


def test_securitytrails_sends_the_key_as_a_header_only() -> None:
    http = FakeHttp({"/domain/example.com": _json_response(ST_DOMAIN)})
    _run(SecurityTrailsModule, http, "example.com", TargetType.DOMAIN)
    for url, headers in http.calls:
        assert "st-key" not in url
        assert headers.get("APIKEY") == "st-key"


def test_subdomain_suffix_match_respects_the_label_boundary():
    """endswith() accepts m.testexample.com as a subdomain of example.com.

    Found by the entity graph: a name that is not under the target turned up as
    a node, and following it would have widened the scan onto a third party.
    """
    from nova_osint.modules.domain import _under

    assert _under("www.example.com", "example.com")
    assert _under("a.b.example.com", "example.com")
    assert _under("example.com", "example.com")
    assert _under("*.example.com", "example.com")
    assert not _under("m.testexample.com", "example.com")
    assert not _under("notexample.com", "example.com")
    assert not _under("", "example.com")
