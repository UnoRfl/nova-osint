"""The pivot- and result-quality rules, each one traceable to a real report.

Every test here was written from a scan that went wrong. The docstrings name
the symptom so that a future change which reintroduces it fails with an
explanation rather than a diff.
"""

from __future__ import annotations

import time

import pytest

from nova_osint.core.config import Config
from nova_osint.core.engine import Budget, Engine, _ModuleHttp, work_key
from nova_osint.core.entities import Entity, EntityType, is_handle_shaped
from nova_osint.core.http import Response
from nova_osint.core.infra import COHOST_CERTAIN, judge_host
from nova_osint.core.models import Confidence, ModuleStatus, ScanResult, TargetType
from nova_osint.core.queryplan import QueryPlanner
from nova_osint.core.search import (
    MojeekEngine,
    SearchService,
    SearxngEngine,
    WikipediaEngine,
)

# ------------------------------------------------- a name is not a handle


@pytest.mark.parametrize("value", [
    "Ryan Rafael",          # the report that started this
    "Mia Khalifa",
    "jireh joy pancho",     # a name guessed from an address's local part
    "  spaced  out  ",
])
def test_a_name_never_becomes_a_handle(value: str) -> None:
    """A name with a space was becoming a USERNAME entity, and the engine then
    pointed github, keybase, npm, webfinger and a 481-site sweep at it. Before
    URLs were escaped that produced seven InvalidURL failures reported as the
    sources' fault; afterwards it produced four hundred real requests that time
    out, which is why a name search looked like it had hung."""
    assert not is_handle_shaped(value)
    assert Entity.make(EntityType.USERNAME, value) is None


@pytest.mark.parametrize("value", [
    "octocat", "john.doe", "mia-khalifa9", "a_b", "x1",
    "eastdakota.com",              # on Bluesky a domain IS the handle
    "miakhalifaa.bsky.social",
    "alice@mastodon.social",       # a fediverse address WebFinger resolves
])
def test_real_handles_still_survive(value: str) -> None:
    """The gate must not be so eager that it loses true positives: Bluesky
    handles are domains and fediverse handles carry an @."""
    assert is_handle_shaped(value)
    assert Entity.make(EntityType.USERNAME, value) is not None


def test_an_address_is_not_a_handle() -> None:
    assert not is_handle_shaped("someone@example.com/../etc")
    assert Entity.make(EntityType.USERNAME, "216.150.1.1") is None


def test_a_handle_cannot_be_prose() -> None:
    assert not is_handle_shaped("x" * 200)


# --------------------------------------------- an address is not a hostname


@pytest.mark.parametrize("etype", [EntityType.DOMAIN, EntityType.HOST])
def test_an_ip_is_an_ip_whatever_the_caller_called_it(etype) -> None:
    """A module emitting a resolved address as a DOMAIN produced a *host*
    node; hosts map to the domain target type; and fourteen domain modules
    were then run against an IP literal. That is the whole of "SPF missing"
    for 216.150.1.1, "no RDAP record for 216.150.1.1", and a search for
    `site:*.216.150.1.1` returning Wikipedia articles on Alberta Highway 10."""
    ent = Entity.make(etype, "216.150.1.1")
    assert ent is not None
    assert ent.etype is EntityType.IP


def test_ipv6_is_recognised_too() -> None:
    ent = Entity.make(EntityType.DOMAIN, "2001:db8::1")
    assert ent is not None and ent.etype is EntityType.IP


def test_a_real_hostname_is_still_a_host() -> None:
    ent = Entity.make(EntityType.DOMAIN, "www.example.com")
    assert ent is not None and ent.etype is EntityType.HOST


def test_an_ip_entity_reaches_only_the_ip_modules() -> None:
    engine = Engine(Config())
    try:
        _, runnable, _ = engine.plan("216.150.1.1", None, None, TargetType.IP)
        names = {m.name for m in runnable}
        assert "mailsec" not in names, "an address has no mail policy"
        assert "whois" not in names or "ip" in names
        assert "websearch" not in names, "site: on an IP is not a question"
    finally:
        engine.close()


# ------------------------------------------------- one subject, one scan


def test_a_site_and_its_front_page_are_one_subject() -> None:
    """dns, mailsec, whois, subdomains, wayback, headers, trackers and
    fingerprint ask the same question of `https://example.com` and
    `example.com`. One scan ran seventy modules where forty would have done,
    and half the duplication was this."""
    url = Entity.make(EntityType.URL, "https://www.example.com")
    host = Entity.make(EntityType.HOST, "www.example.com")
    assert work_key(url) == work_key(host)


def test_a_url_with_a_path_is_its_own_subject() -> None:
    page = Entity.make(EntityType.URL, "https://www.example.com/report.pdf")
    host = Entity.make(EntityType.HOST, "www.example.com")
    assert work_key(page) != work_key(host), \
        "a document is not the site it sits on"


def test_unrelated_entities_keep_their_own_keys() -> None:
    a = Entity.make(EntityType.IP, "1.2.3.4")
    b = Entity.make(EntityType.DOMAIN, "example.com")
    assert work_key(a) != work_key(b)


# ------------------------------------------- co-location is not a relation


def test_an_anycast_edge_is_recognised_by_its_own_name() -> None:
    """The scan that prompted this followed forty co-hosted names off a Vercel
    anycast address - cigar.cafe, ournews.school, 2026.fragile.ventures - none
    of which have anything to do with a jeweller in Singapore."""
    verdict = judge_host(cohosted=40, as_owner="Amazon.com, Inc.",
                         cert_cn="no-sni.vercel-infra.com")
    assert verdict and verdict.certain
    assert verdict.basis == "naming"


def test_a_cloud_as_owner_is_enough_on_its_own() -> None:
    assert judge_host(as_owner="Cloudflare, Inc.").basis == "ownership"
    assert judge_host(as_owner="Amazon Technologies Inc.").shared


def test_population_alone_decides_when_nothing_is_recognised() -> None:
    """The signal that needs no list, and so works for a host nobody has
    heard of."""
    assert judge_host(cohosted=COHOST_CERTAIN, as_owner="Obscure Hosting Oy")
    assert judge_host(cohosted=COHOST_CERTAIN).basis == "population"


def test_a_few_neighbours_are_a_genuine_lead_and_are_kept() -> None:
    """Small organisations really do host their own sites together, and that
    is a link worth following. The rule must not swallow it."""
    assert not judge_host(cohosted=3, as_owner="Example Telecom AB")
    assert not judge_host(cohosted=0, ptr="mail.mycompany.example")


def test_a_targets_own_reverse_dns_is_not_provider_space() -> None:
    assert not judge_host(cohosted=2, ptr="server12.mycompany.example")


# ------------------------------- an engine is not sent operators it lacks


def test_an_encyclopedia_is_not_asked_a_site_query() -> None:
    """`site:*.216.150.1.1 -www` went to Wikipedia's search API verbatim and
    came back with Alberta Highway 10, Papyrus Oxyrhynchus 80 and the 2004
    Masters - all recorded as findings about an IP address."""
    query = next(q for q in QueryPlanner().plan_domain("example.com")
                 if "site:*." in q.text)
    text, skip = SearchService._phrase_for(WikipediaEngine(None, None), query)
    assert text == "" and "site:" in skip


def test_an_engine_that_implements_the_operator_gets_it_intact() -> None:
    query = next(q for q in QueryPlanner().plan_domain("example.com")
                 if "site:*." in q.text)
    text, skip = SearchService._phrase_for(MojeekEngine(None, None), query)
    assert skip == "" and "site:*.example.com" in text


def test_a_partial_degrade_leaves_a_query_somebody_could_have_typed() -> None:
    """Stripping `site:a.com OR site:b.com` used to eat the closing bracket and
    leave `"example.com" (`, which asks an engine for an open parenthesis."""
    query = next(q for q in QueryPlanner().plan_domain("example.com")
                 if "site:github.com" in q.text)
    text, skip = SearchService._phrase_for(WikipediaEngine(None, None), query)
    if not skip:
        assert text.count("(") == text.count(")")
        assert " OR OR " not in text
        assert not text.rstrip().endswith("(")


def test_a_searxng_instance_inherits_its_upstream_operators() -> None:
    query = next(q for q in QueryPlanner().plan_domain("example.com")
                 if "site:*." in q.text)
    text, skip = SearchService._phrase_for(SearxngEngine(None, None), query)
    assert skip == "" and text == query.text


def test_a_plain_query_is_untouched_for_every_engine() -> None:
    plain = next(q for q in QueryPlanner().plan_person("Ada Lovelace")
                 if not q.operators)
    for engine in (WikipediaEngine(None, None), MojeekEngine(None, None)):
        text, skip = SearchService._phrase_for(engine, plain)
        assert skip == "" and text == plain.text


# ------------------------------------- an unverified hit is not a confirmed one


class _Fetch:
    """A fetcher whose control probes all fail, as they do under rate limits."""

    def __init__(self, control_answers: bool | None) -> None:
        self.control_answers = control_answers

    def map(self, fn, items):
        return [fn(i) for i in items]


def _hit(site: str = "BoardGameGeek") -> dict:
    return {"site": site, "url": f"https://{site}/u/x", "outcome": "answered",
            "claimed": True, "status": 200, "access": "ok",
            "method": "status_code", "confidence": Confidence.LIKELY,
            "nsfw": False, "meta": {"url": f"https://{site}/u/" + "{}",
                                    "errorType": "status_code"}}


def _verify_with(control):
    from nova_osint.modules.username import UsernameModule

    module = UsernameModule(_Fetch(None), Config())
    module._check = lambda site, meta, handle: control  # type: ignore[assignment]
    return module._verify([_hit()], {})


def test_a_control_probe_that_failed_does_not_confirm_a_hit() -> None:
    """`if ctrl and ctrl["claimed"]` is False when ctrl is None, so a control
    probe that timed out promoted its hit to CONFIRMED. Under a sweep of 481
    sites with per-host rate limiting, control probes fail in bulk - which is
    how one scan returned fifty-six "confirmed" accounts on sites that had
    never been verified at all."""
    kept = _verify_with(None)
    assert len(kept) == 1
    assert kept[0]["confidence"] is not Confidence.CONFIRMED
    assert kept[0]["verified"] is False
    assert "control probe" in kept[0]["unverified_reason"]


def test_a_control_the_site_rejects_verifies_nothing() -> None:
    not_applicable = {"site": "X", "outcome": "not-applicable", "claimed": False}
    kept = _verify_with(not_applicable)
    assert kept[0]["verified"] is False
    assert "username rules" in kept[0]["unverified_reason"]


def test_a_site_that_claims_the_control_is_dropped() -> None:
    claims_everything = {"site": "X", "outcome": "answered", "claimed": True}
    assert _verify_with(claims_everything) == []


def test_a_properly_rejected_control_confirms_the_hit() -> None:
    rejected = {"site": "X", "outcome": "answered", "claimed": False}
    kept = _verify_with(rejected)
    assert kept[0]["confidence"] is Confidence.CONFIRMED
    assert kept[0]["verified"] is True


def test_the_control_handle_is_shaped_to_the_site_that_will_judge_it() -> None:
    from nova_osint.modules.username import _control_for

    only_letters = _control_for({"regexCheck": r"^[a-z]+$"})
    assert only_letters.isalpha(), \
        "a control the site rejects tests its input validation, not its users"


# ---------------------------------------- one slow module is not a hung scan


def test_past_its_deadline_a_module_stops_making_requests() -> None:
    """A 481-site sweep, doubled by verification and serialised by rate
    limiting, can hold a run open for minutes with nothing on screen - which
    is indistinguishable from a hang to the person watching."""
    class Boom:
        def get(self, url, **kw):  # pragma: no cover - must not be reached
            raise AssertionError("a starved module must not open a socket")

    http = _ModuleHttp(Boom(), "username", deadline=time.monotonic() - 1)
    resp = http.get("https://example.test/u/x")
    assert resp.status == 0
    assert "time limit" in (resp.error or "")
    assert http.starved == 1


def test_before_its_deadline_a_module_is_untouched() -> None:
    class Ok:
        def get(self, url, **kw):
            return Response(url=url, status=200, body=b"hi")

    http = _ModuleHttp(Ok(), "m", deadline=time.monotonic() + 60)
    assert http.get("https://example.test/").ok
    assert http.starved == 0


def test_no_deadline_means_no_deadline() -> None:
    class Ok:
        def get(self, url, **kw):
            return Response(url=url, status=200, body=b"hi")

    http = _ModuleHttp(Ok(), "m")
    assert http.get("https://example.test/").ok


# --------------------------------------------------- the documents module


def test_a_document_target_without_a_scheme_is_formatted_not_failed() -> None:
    """`ValueError: unknown url type: 'www.designsbyracquel.com'` appeared four
    times in one report as "documents — failed", which reads as the source
    having broken rather than as NOVA handing urllib a value it never
    formatted."""
    from nova_osint.modules.documents import DocumentModule

    asked: list[str] = []

    class Fetch:
        def get(self, url, **kw):
            asked.append(url)
            return Response(url=url, status=200, body=b"<html></html>",
                            headers={"content-type": "text/html"})

    res = ScanResult(module="documents", target="www.example.com",
                     target_type=TargetType.URL)
    DocumentModule(Fetch(), Config()).run("www.example.com", res)
    assert asked == ["https://www.example.com"]
    assert res.status is not ModuleStatus.FAILED


# ------------------------------------------------------- the whole walk


def test_an_expansion_no_longer_scans_an_address_as_a_website(monkeypatch) -> None:
    """The end-to-end shape of the designsbyracquel report: a URL seed whose
    address became a host entity and drew the full domain module set."""
    seen: list[tuple[str, str, int]] = []

    class Watch(Engine):
        def _run_all(self, modules, target, ttype, on_result, subject=None):
            seen.append((target, ttype.value, len(modules)))
            return []

    engine = Watch(Config())
    try:
        graph_seed = Entity.make(EntityType.IP, "216.150.1.1")
        assert graph_seed is not None and graph_seed.etype is EntityType.IP
        engine.investigate("https://example.com", target_type=TargetType.URL,
                           budget=Budget.quick())
    finally:
        engine.close()
    for target, ttype, _count in seen:
        assert not (ttype == "domain" and target.replace(".", "").isdigit()), \
            f"{target} was scanned as a website"


# ------------------------------------- declining to follow a lead is a finding


def test_leads_below_the_evidence_floor_are_named_not_dropped() -> None:
    """A scan of a common name finds several accounts sharing the display
    name and follows none of them. That is the right call - following them is
    how these tools assemble a portrait of five different people - and it used
    to read as "found nothing", because frontier() filters before the
    unexplored list is built."""
    from nova_osint.core.engine import Expansion
    from nova_osint.core.models import Investigation
    from nova_osint.core.report import declined_note, declined_rows

    inv = Investigation(target="Mia Khalifa", target_type=TargetType.PERSON)
    inv.expansion = Expansion(below_floor=[("username:miakhalifaa", 0.0273),
                                           ("username:mia-khalifa9", 0.0273)])
    rows = declined_rows(inv)
    assert [eid for eid, _ in rows] == ["username:miakhalifaa",
                                        "username:mia-khalifa9"]
    assert "-K" in declined_note(inv), "it must name the way out"


def test_a_scan_with_nothing_declined_says_nothing() -> None:
    from nova_osint.core.models import Investigation
    from nova_osint.core.report import declined_note, declined_rows

    inv = Investigation(target="x", target_type=TargetType.DOMAIN)
    assert declined_rows(inv) == [] and declined_note(inv) == ""


def test_declined_leads_reach_the_markdown_report() -> None:
    from nova_osint.core import report
    from nova_osint.core.engine import Expansion
    from nova_osint.core.models import Investigation

    inv = Investigation(target="Mia Khalifa", target_type=TargetType.PERSON)
    inv.expansion = Expansion(below_floor=[("username:miakhalifaa", 0.0273)])
    md = report.render_markdown(inv)
    assert "Leads found but not followed" in md
    assert "username:miakhalifaa" in md


def test_the_suite_is_offline_by_construction() -> None:
    """conftest closes the socket for every unmarked test. This asserts the
    guard is actually installed, so removing it fails here rather than
    silently reintroducing ninety-five second tests."""
    import pytest as _pytest

    from nova_osint.core.config import Config
    from nova_osint.core.http import Fetcher

    with Fetcher(timeout=1, retries=0, cache_dir=None) as fetcher,             _pytest.raises(AssertionError, match="offline"):
        fetcher._once("https://example.com", None, True, "GET", None, None)
    assert Config() is not None
