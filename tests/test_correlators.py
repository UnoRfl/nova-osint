"""Offline tests for the correlator modules.

No network: each module is handed a fake fetcher replaying a saved payload,
which is the only honest way to test a parser. A live call proves the network
works, not that the code reads the answer correctly.

The property most of these check is not "did it find the value" but "did it emit
the right *entity*", because the entity is what does the linking. A module that
reports a tracker id as text and never emits the node has found nothing the
graph can use.
"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from nova_osint.core.config import Config
from nova_osint.core.entities import Entity, EntityType
from nova_osint.core.http import Response
from nova_osint.core.models import ModuleStatus, ScanResult, Severity, TargetType
from nova_osint.modules.correlators import (
    TRACKER_NOISE,
    ConfusableModule,
    FingerprintModule,
    KeybaseModule,
    KeyModule,
    PackageModule,
    TrackerModule,
    WebFingerModule,
    ssh_fingerprint,
    structure_hash,
    tracker_ids,
)


class FakeHttp:
    """Canned response per URL fragment; records what was asked for."""

    def __init__(self, routes: dict[str, Response], default: int = 404) -> None:
        self.routes = routes
        self.default = default
        self.calls: list[str] = []

    def get(self, url: str, **kw) -> Response:
        self.calls.append(url)
        for fragment, response in self.routes.items():
            if fragment in url:
                return response
        return Response(url=url, status=self.default)

    def get_json(self, url: str, default=None, **kw):
        return self.get(url, **kw).json(default)

    def map(self, fn, items):
        return [fn(i) for i in items]


def _resp(body: str | bytes, status: int = 200, ctype: str = "text/html") -> Response:
    if isinstance(body, str):
        body = body.encode()
    return Response(url="https://example.test/", status=status,
                    headers={"content-type": ctype}, body=body)


def _json(payload, status: int = 200) -> Response:
    return _resp(json.dumps(payload), status, "application/json")


def _run(cls, http, target, ttype) -> ScanResult:
    result = ScanResult(module=cls.name, target=target, target_type=ttype)
    result.subject = Entity.make(
        {TargetType.DOMAIN: EntityType.DOMAIN, TargetType.USERNAME: EntityType.USERNAME,
         TargetType.EMAIL: EntityType.EMAIL, TargetType.URL: EntityType.URL}[ttype],
        target)
    cls(http, Config(cache_dir=None)).run(target, result)
    return result


def _labels(result):
    return {f.label for f in result.findings}


def _entities(result):
    return {e.eid for e in result.nodes}


def _kinds(result):
    return {link.kind for link in result.links}


# ---------------------------------------------------------------------------
# trackers
# ---------------------------------------------------------------------------

PAGE_WITH_TRACKERS = """
<html><head>
<script async src="https://www.googletagmanager.com/gtag/js?id=UA-123456-1"></script>
<script>gtag('config', 'G-ABCD123456');</script>
<script>(function(w,d,s,l,i){})(window,document,'script','dataLayer','GTM-ABCD12');</script>
<script>fbq('init', '123456789012345');</script>
<script src="https://mc.yandex.ru/watch/98765432"></script>
<ins class="adsbygoogle" data-ad-client="ca-pub-1234567890123456"></ins>
</head><body><h1>hi</h1></body></html>
"""


def test_tracker_ids_are_extracted():
    found = dict(tracker_ids(PAGE_WITH_TRACKERS))
    assert found["google-analytics"] == "UA-123456-1"
    assert found["google-analytics-4"] == "G-ABCD123456"
    assert found["google-tag-manager"] == "GTM-ABCD12"
    assert found["meta-pixel"] == "123456789012345"
    assert found["yandex-metrica"] == "98765432"
    assert found["adsense"] == "ca-pub-1234567890123456"


def test_vendor_placeholder_ids_are_ignored():
    """Every copy-pasted snippet shares these; linking on them links nothing."""
    page = "<script>gtag('config','UA-XXXXX-Y');ga('create','G-XXXXXXXXXX');</script>"
    assert tracker_ids(page) == []
    assert "UA-XXXXX-Y" in TRACKER_NOISE


def test_tracker_module_emits_an_entity_per_id():
    http = FakeHttp({"example.com": _resp(PAGE_WITH_TRACKERS)})
    res = _run(TrackerModule, http, "example.com", TargetType.DOMAIN)
    assert "google-analytics/UA-123456-1" in {e.value for e in res.nodes}
    assert all(e.etype is EntityType.TRACKER for e in res.nodes)
    assert _kinds(res) == {"tracker-id-shared"}


def test_two_sites_sharing_a_tracker_connect_through_it():
    """The point of the whole design: no code compares A to B."""
    from nova_osint.core.engine import Engine
    from nova_osint.core.graph import EntityGraph

    graph = EntityGraph(Entity.make(EntityType.DOMAIN, "a.test"))
    for site in ("a.test", "b.test"):
        http = FakeHttp({site: _resp(PAGE_WITH_TRACKERS)})
        Engine.merge(graph, _run(TrackerModule, http, site, TargetType.DOMAIN))
    tracker = "tracker:google-analytics/UA-123456-1"
    assert graph.neighbors(tracker) == {"domain:a.test", "domain:b.test"}


def test_a_page_with_no_trackers_says_so_rather_than_staying_silent():
    http = FakeHttp({"example.com": _resp("<html><body>nothing</body></html>")})
    res = _run(TrackerModule, http, "example.com", TargetType.DOMAIN)
    assert "analytics" in _labels(res) and not res.nodes


def test_an_unreachable_site_is_unavailable_not_empty():
    http = FakeHttp({}, default=503)
    res = _run(TrackerModule, http, "example.com", TargetType.DOMAIN)
    assert res.status is ModuleStatus.UNAVAILABLE and res.status_reason


# ---------------------------------------------------------------------------
# fingerprints
# ---------------------------------------------------------------------------


def test_structure_hash_ignores_text_but_not_markup():
    a = "<html><body><h1>One headline</h1><p>Body</p></body></html>"
    b = "<html><body><h1>Different words entirely</h1><p>Other</p></body></html>"
    c = "<html><body><h1>One headline</h1><div>Body</div></body></html>"
    assert structure_hash(a) == structure_hash(b), "content must not change the shape"
    assert structure_hash(a) != structure_hash(c), "markup must"


def test_favicon_and_structure_become_entities():
    icon = b"\x00\x01icon-bytes"
    http = FakeHttp({"favicon.ico": _resp(icon, ctype="image/x-icon"),
                     "example.com": _resp("<html><body><p>x</p></body></html>")})
    res = _run(FingerprintModule, http, "example.com", TargetType.DOMAIN)
    digest = hashlib.sha256(icon).hexdigest()
    assert f"favicon:{digest}" in _entities(res)
    assert any(e.etype is EntityType.FILEHASH and e.value.startswith("dom/")
               for e in res.nodes)
    assert "favicon-hash" in _kinds(res) and "page-structure-hash" in _kinds(res)


def test_only_third_party_script_hosts_are_reported():
    page = ("<script src='https://example.com/own.js'></script>"
            "<script src='https://cdn.other.test/lib.js'></script>")
    http = FakeHttp({"favicon.ico": _resp(b"", status=404),
                     "example.com": _resp(page)})
    res = _run(FingerprintModule, http, "example.com", TargetType.DOMAIN)
    hosts = next(f for f in res.findings if f.label == "third-party script hosts")
    assert hosts.value == ["cdn.other.test"]


def test_a_missing_favicon_does_not_fail_the_module():
    http = FakeHttp({"favicon.ico": _resp(b"", status=404),
                     "example.com": _resp("<html><p>x</p></html>")})
    res = _run(FingerprintModule, http, "example.com", TargetType.DOMAIN)
    assert res.status is ModuleStatus.SUCCESS
    assert "DOM structure sha256" in _labels(res)


# ---------------------------------------------------------------------------
# public keys
# ---------------------------------------------------------------------------

_KEY_BLOB = base64.b64encode(b"fake-ssh-key-material-for-testing").decode()


def test_ssh_fingerprint_matches_the_openssh_format():
    fp = ssh_fingerprint(_KEY_BLOB)
    assert fp.startswith("SHA256:") and not fp.endswith("=")
    expected = base64.b64encode(
        hashlib.sha256(base64.b64decode(_KEY_BLOB)).digest()).decode().rstrip("=")
    assert fp == f"SHA256:{expected}"


def test_malformed_key_material_is_data_not_an_error():
    assert ssh_fingerprint("!!! not base64 !!!") == ""


def test_keys_become_the_strongest_kind_of_entity():
    http = FakeHttp({".keys": _resp(f"ssh-ed25519 {_KEY_BLOB} alice@host"),
                     ".gpg": _resp("-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n")})
    res = _run(KeyModule, http, "alice", TargetType.USERNAME)
    assert _kinds(res) == {"key-fingerprint-shared"}
    assert any(e.value.startswith("ssh/SHA256:") for e in res.nodes)
    assert any(e.value.startswith("gpg/") for e in res.nodes)


def test_two_handles_holding_one_key_are_linked():
    from nova_osint.core.engine import Engine
    from nova_osint.core.graph import EntityGraph

    graph = EntityGraph(Entity.make(EntityType.USERNAME, "alice"))
    http = FakeHttp({".keys": _resp(f"ssh-ed25519 {_KEY_BLOB} k"),
                     ".gpg": _resp("", status=404)})
    for handle in ("alice", "alice-work"):
        Engine.merge(graph, _run(KeyModule, http, handle, TargetType.USERNAME))
    key = next(eid for eid in graph.nodes if eid.startswith("key:ssh/"))
    assert graph.neighbors(key) == {"username:alice", "username:alice-work"}
    edge = graph.edges_of(key)[0]
    assert edge.llr >= 7.0, "a shared private key is near-certain evidence"
    assert edge.grade.startswith("A")


def test_a_missing_github_account_is_reported_plainly():
    res = _run(KeyModule, FakeHttp({}, default=404), "nobody", TargetType.USERNAME)
    assert "github keys" in _labels(res) and not res.nodes


def test_github_being_down_is_not_an_empty_result():
    res = _run(KeyModule, FakeHttp({}, default=503), "alice", TargetType.USERNAME)
    assert res.status is ModuleStatus.UNAVAILABLE


# ---------------------------------------------------------------------------
# keybase
# ---------------------------------------------------------------------------

KEYBASE = {"them": [{"basics": {"username": "alice"}, "proofs_summary": {"all": [
    {"proof_type": "twitter", "nametag": "alice_t",
     "service_url": "https://twitter.com/alice_t"},
    {"proof_type": "github", "nametag": "alice-gh",
     "service_url": "https://github.com/alice-gh"},
    {"proof_type": "dns", "nametag": "alice.test",
     "service_url": "https://alice.test"},
]}}]}


def test_keybase_proofs_are_confirmed_and_high_interest():
    http = FakeHttp({"keybase.io": _json(KEYBASE)})
    res = _run(KeybaseModule, http, "alice", TargetType.USERNAME)
    assert {f.severity for f in res.findings} == {Severity.HIGH}
    assert _kinds(res) == {"keybase-proof"}
    assert "username:alice-gh" in _entities(res)
    # A DNS proof is a domain, not a handle; typing it wrong breaks every pivot.
    assert "domain:alice.test" in _entities(res)


def test_keybase_account_without_proofs():
    http = FakeHttp({"keybase.io": _json({"them": [{"proofs_summary": {"all": []}}]})})
    res = _run(KeybaseModule, http, "alice", TargetType.USERNAME)
    assert "no verified proofs" in str(res.findings[0].value)


def test_keybase_no_such_account():
    http = FakeHttp({"keybase.io": _json({"them": []})})
    res = _run(KeybaseModule, http, "nobody", TargetType.USERNAME)
    assert "no account" in str(res.findings[0].value) and not res.nodes


def test_keybase_html_error_page_is_unavailable_not_empty():
    http = FakeHttp({"keybase.io": _resp("<html>503</html>")})
    res = _run(KeybaseModule, http, "alice", TargetType.USERNAME)
    assert res.status is ModuleStatus.UNAVAILABLE


# ---------------------------------------------------------------------------
# packages
# ---------------------------------------------------------------------------


NPM_SEARCH = {"objects": [
    {"package": {"name": "left-pad",
                 "publisher": {"username": "alice", "email": "alice@example.com"}}},
    {"package": {"name": "right-pad",
                 "publisher": {"username": "alice", "email": "alice@example.com"}}},
    {"package": {"name": "co-maintained",
                 "publisher": {"username": "bob", "email": "bob@example.com"}}},
]}


def test_npm_publisher_email_is_extracted_and_typed():
    http = FakeHttp({"registry.npmjs.org": _json(NPM_SEARCH)})
    res = _run(PackageModule, http, "alice", TargetType.USERNAME)
    assert "npm publisher email" in _labels(res)
    assert "email:alice@example.com" in _entities(res)
    packages = next(f for f in res.findings if f.label == "npm packages")
    assert packages.value == ["co-maintained", "left-pad", "right-pad"]


def test_npm_does_not_attribute_a_co_maintainers_address_to_the_target():
    """A package has several publishers; only one of them is who we asked about."""
    http = FakeHttp({"registry.npmjs.org": _json(NPM_SEARCH)})
    res = _run(PackageModule, http, "alice", TargetType.USERNAME)
    assert "email:bob@example.com" not in _entities(res)
    assert "bob@example.com" not in str([f.value for f in res.findings])


def test_crates_and_docker_records():
    http = FakeHttp({
        "crates.io": _json({"user": {"login": "alice", "name": "Alice Example"}}),
        "hub.docker.com": _json({"username": "alice", "company": "Example Ltd",
                                 "full_name": "Alice Example"}),
    })
    res = _run(PackageModule, http, "alice", TargetType.USERNAME)
    assert "crates.io account" in _labels(res)
    assert "Docker Hub company" in _labels(res)
    assert "org:example ltd" in _entities(res)


def test_no_registry_account_anywhere():
    res = _run(PackageModule, FakeHttp({}, default=404), "nobody", TargetType.USERNAME)
    assert "package registries" in _labels(res) and not res.nodes


def test_one_registry_erroring_does_not_hide_the_others():
    http = FakeHttp({"registry.npmjs.org": _resp("", status=500),
                     "crates.io": _json({"user": {"login": "alice"}})})
    res = _run(PackageModule, http, "alice", TargetType.USERNAME)
    assert "crates.io account" in _labels(res)
    assert any("npm answered 500" in e for e in res.errors)


# ---------------------------------------------------------------------------
# webfinger
# ---------------------------------------------------------------------------


def test_webfinger_resolves_a_full_address():
    http = FakeHttp({"webfinger": _json({
        "subject": "acct:alice@fosstodon.org",
        "links": [{"rel": "self", "href": "https://fosstodon.org/users/alice"}]})})
    res = _run(WebFingerModule, http, "alice@fosstodon.org", TargetType.EMAIL)
    assert "fediverse account" in _labels(res)
    assert _kinds(res) == {"webfinger-proof"}


def test_webfinger_names_the_instances_it_asked_rather_than_claiming_none_exist():
    """'Not on these four' is a different claim from 'no fediverse account'."""
    res = _run(WebFingerModule, FakeHttp({}, default=404), "alice",
               TargetType.USERNAME)
    note = next(f for f in res.findings if f.label == "fediverse")
    for host in WebFingerModule.INSTANCES:
        assert host in str(note.value)


# ---------------------------------------------------------------------------
# confusables
# ---------------------------------------------------------------------------


def _crtsh(names):
    return _json([{"name_value": "\n".join(names)}])


def test_look_alike_domains_are_found():
    http = FakeHttp({"crt.sh": _crtsh(
        ["paypa1.com", "paypal.com", "www.paypal.com", "paypaI.com",
         "totallyunrelated.com"])})
    res = _run(ConfusableModule, http, "paypal.com", TargetType.DOMAIN)
    found = next(f for f in res.findings if f.label == "look-alike domains")
    assert "paypa1.com" in found.value
    assert "paypal.com" not in found.value, "the target is not its own impostor"
    assert "totallyunrelated.com" not in found.value


def test_look_alikes_are_reported_but_never_followed():
    """Someone else's domain. Crawling it widens the case onto a third party."""
    from nova_osint.core.engine import Engine
    from nova_osint.core.graph import EntityGraph

    http = FakeHttp({"crt.sh": _crtsh(["paypa1.com", "paypal.com"])})
    res = _run(ConfusableModule, http, "paypal.com", TargetType.DOMAIN)
    graph = EntityGraph(res.subject)
    Engine.merge(graph, res)
    graph.rescore()
    assert "domain:paypa1.com" in graph.nodes
    assert "domain:paypa1.com" not in {n.entity.eid for n in graph.frontier()}
    edge = graph.between("domain:paypal.com", "domain:paypa1.com")[0]
    assert edge.llr == 0.0 and edge.label == "looks-like"


def test_a_short_name_is_refused_rather_than_drowning_in_false_positives():
    res = _run(ConfusableModule, FakeHttp({}), "bbc.co.uk", TargetType.DOMAIN)
    assert "too short" in str(res.findings[0].value)


def test_confusables_with_nothing_to_report():
    http = FakeHttp({"crt.sh": _crtsh(["example.com", "www.example.com"])})
    res = _run(ConfusableModule, http, "example.com", TargetType.DOMAIN)
    assert "none in CT" in str(res.findings[0].value)


def test_crtsh_down_is_unavailable():
    http = FakeHttp({"crt.sh": _resp("<html>gateway timeout</html>", status=504)})
    res = _run(ConfusableModule, http, "example.com", TargetType.DOMAIN)
    assert res.status is ModuleStatus.UNAVAILABLE


# ---------------------------------------------------------------------------
# registration
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["trackers", "fingerprint", "keys", "keybase",
                                  "packages", "webfinger", "confusables"])
def test_module_is_registered_and_declares_itself(name):
    from nova_osint.core.registry import get_module

    cls = get_module(name)
    assert cls is not None
    assert cls.description and cls.accepts
    assert cls.requires_key is None, "these are all keyless by design"


def test_modules_that_touch_the_target_declare_themselves_active():
    """--passive is a hard gate, and it only works if modules are honest."""
    from nova_osint.core.registry import get_module

    assert get_module("trackers").active, "it fetches the target's own page"
    assert get_module("fingerprint").active
    for passive in ("keys", "keybase", "packages", "confusables"):
        assert not get_module(passive).active


# ---------------------------------------------------------------------------
# commit-email attribution
# ---------------------------------------------------------------------------


def test_only_attributed_commits_count_as_the_targets_own_address():
    """A co-contributor's address asserted as the target's is a false identity.

    GitHub leaves `author` null when it cannot map a commit to an account,
    which in a busy repo is most of them. Attribution has to be positive.
    """
    from nova_osint.modules.github import GithubModule

    commits = [
        {"author": {"login": "alice"},
         "commit": {"author": {"email": "alice@example.com", "name": "Alice",
                               "date": "2026-01-01T10:00:00+01:00"}}},
        {"author": None,  # GitHub could not attribute this one
         "commit": {"author": {"email": "stranger@elsewhere.test", "name": "S",
                               "date": "2026-01-01T10:00:00+01:00"}}},
        {"author": {"login": "bob"},
         "commit": {"author": {"email": "bob@example.com", "name": "Bob",
                               "date": "2026-01-01T10:00:00+01:00"}}},
    ]
    http = FakeHttp({"/commits": _json(commits)})
    res = ScanResult(module="github", target="alice", target_type=TargetType.USERNAME)
    res.subject = Entity.make(EntityType.USERNAME, "alice")
    GithubModule(http, Config(cache_dir=None))._commits(
        "alice", [{"full_name": "alice/repo"}], res)

    own = {link.dst.value for link in res.links if link.kind == "commit-email"}
    assert own == {"alice@example.com"}
    weak = {link.dst.value for link in res.links if link.kind == "mentioned"}
    # Both of the others are still reported - who else commits here is a real
    # lead - but as contributors, at almost no weight, never as her address.
    assert weak == {"stranger@elsewhere.test", "bob@example.com"}
    assert "bob@example.com" not in own
