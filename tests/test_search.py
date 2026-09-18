"""Search engines, result normalisation, robots compliance and query planning.

No socket is opened anywhere in this file. Engines are exercised through their
``parse`` classmethods and through a fake fetcher that returns fixtures, which
is also the shape a real engine failure takes, so the fallback paths are
tested rather than assumed.
"""

from __future__ import annotations

import json

import pytest

from nova_osint.core.acquisition import Method
from nova_osint.core.http import Response
from nova_osint.core.providers import Health, ProviderHealth
from nova_osint.core.queryplan import (
    Category,
    QueryPlanner,
    handle_candidates,
    name_forms,
    name_rarity,
)
from nova_osint.core.robots import AllowAll, RobotsCache
from nova_osint.core.search import (
    DuckDuckGoLiteEngine,
    MarginaliaEngine,
    MojeekEngine,
    SearchResult,
    SearchService,
    SearxngEngine,
    WikipediaEngine,
    canonical_url,
    cluster,
    independent,
    merge,
)


class FakeFetcher:
    """Returns a canned reply per URL substring, and records what was asked."""

    def __init__(self, replies: dict[str, Response] | None = None) -> None:
        self.replies = replies or {}
        self.asked: list[str] = []

    def get(self, url: str, **kw) -> Response:
        self.asked.append(url)
        for fragment, resp in self.replies.items():
            if fragment in url:
                return resp
        return Response(url=url, status=404, body=b"")


def ok(body: str, url: str = "https://example.test/") -> Response:
    return Response(url=url, status=200, body=body.encode("utf-8"))


class Cfg:
    """The smallest thing that looks like a Config to the engines."""

    def __init__(self, **options) -> None:
        self.options = options

    def option(self, name, default=None):
        return self.options.get(name, default)

    def has(self, name):
        return False


# ------------------------------------------------------------ canonical URLs


@pytest.mark.parametrize("raw,expected", [
    ("https://www.Example.com/Page/", "https://example.com/Page"),
    ("https://example.com/a?utm_source=x&id=2#frag", "https://example.com/a?id=2"),
    ("https://example.com/?fbclid=123", "https://example.com/"),
    ("HTTPS://EXAMPLE.COM/a", "https://example.com/a"),
])
def test_canonical_url_gives_one_spelling_per_document(raw, expected) -> None:
    assert canonical_url(raw) == expected


def test_canonical_url_unwraps_a_serp_redirector() -> None:
    wrapped = ("https://duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.org"
               "%2Fpost&rut=abc")
    assert canonical_url(wrapped) == "https://example.org/post"


def test_canonical_url_keeps_a_query_that_is_the_document() -> None:
    # On a great many sites the query *is* the page; dropping it would merge
    # unrelated documents into one.
    url = "https://example.com/view.php?id=44&page=2"
    assert canonical_url(url) == "https://example.com/view.php?id=44&page=2"


# ------------------------------------------------------- merging and grouping


def _result(engine: str, url: str, title: str = "T", snippet: str = "",
            position: int = 1) -> SearchResult:
    return SearchResult(query="q", engine=engine, title=title, url=url,
                        snippet=snippet, position=position)


def test_two_engines_returning_one_document_produce_one_row() -> None:
    merged = merge([
        _result("wikipedia", "https://example.com/a", position=3),
        _result("marginalia", "https://www.example.com/a/", position=1),
    ])
    assert len(merged) == 1
    assert set(merged[0].engines) == {"wikipedia", "marginalia"}
    assert merged[0].position == 1, "the best position anywhere is the one kept"


def test_syndicated_copies_are_one_independent_source() -> None:
    story = ("Ada Lovelace appointed to the board of the Analytical Engine "
             "Company in a move widely reported today")
    results = [
        _result("e", "https://news-a.test/x", "Lovelace joins board", story),
        _result("e", "https://news-b.test/y", "Lovelace joins board", story),
        _result("e", "https://news-c.test/z", "Lovelace joins board", story),
    ]
    cluster(results)
    assert len({r.group for r in results}) == 1
    assert independent(results) == 1, \
        "one wire story on three sites is one source, not three"


def test_genuinely_different_pages_stay_independent() -> None:
    results = [
        _result("e", "https://a.test/1", "Conference programme",
                "Ada Lovelace will speak about analytical engines at the "
                "spring meeting in Turin"),
        _result("e", "https://b.test/2", "Staff directory",
                "Ada Lovelace, senior mathematician, joined the institute in "
                "eighteen forty and leads the computation group"),
    ]
    cluster(results)
    assert independent(results) == 2


def test_a_result_with_almost_no_text_falls_back_to_its_site() -> None:
    results = [_result("e", "https://a.test/1", "Hi"), _result("e", "https://b.test/2", "Yo")]
    cluster(results)
    assert {r.group for r in results} == {"site:a.test", "site:b.test"}


# ----------------------------------------------------------- engine parsers


def test_wikipedia_parser_reads_the_documented_shape() -> None:
    payload = json.dumps({"query": {"search": [
        {"title": "Ada Lovelace", "snippet": 'was an <span class="hl">English</span> mathematician'},
        {"title": "Analytical Engine", "snippet": "a machine"},
    ]}})
    got = WikipediaEngine.parse(payload, "ada lovelace")
    assert [r.title for r in got] == ["Ada Lovelace", "Analytical Engine"]
    assert got[0].url == "https://en.wikipedia.org/wiki/Ada_Lovelace"
    assert "<span" not in got[0].snippet, "markup must not reach the report"
    assert got[0].position == 1


def test_marginalia_parser_reads_its_public_api() -> None:
    payload = json.dumps({"results": [
        {"url": "https://example.org/ada", "title": "Ada",
         "description": "notes on the engine"},
    ]})
    got = MarginaliaEngine.parse(payload, "ada")
    assert got[0].url == "https://example.org/ada"
    assert got[0].snippet == "notes on the engine"


def test_searxng_parser_reads_its_json_api() -> None:
    payload = json.dumps({"results": [
        {"url": "https://example.org/a", "title": "A", "content": "text",
         "positions": [2], "category": "general"},
    ]})
    got = SearxngEngine.parse(payload, "q")
    assert got[0].position == 2 and got[0].result_type == "general"


def test_a_serp_parser_survives_a_layout_it_has_never_seen() -> None:
    # The whole reason the SERP parser is link-based rather than class-based:
    # a redesign should cost precision, not the entire engine.
    html = """
      <div class="brand-new-wrapper">
        <a href="https://example.org/one">A real result title</a>
        <a href="https://www.mojeek.com/about">About Mojeek</a>
        <a href="/relative/link">relative</a>
        <a href="https://example.net/two">Another result here</a>
      </div>
    """
    got = MojeekEngine.parse(html, "q")
    urls = [r.url for r in got]
    assert "https://example.org/one" in urls
    assert "https://example.net/two" in urls
    assert not any("mojeek.com" in u for u in urls), "self-links are not results"
    assert not any(u.endswith("/relative/link") for u in urls)


def test_ddg_lite_parser_unwraps_its_own_redirector() -> None:
    html = ('<a href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.org%2Fp">'
            'Example page title</a>')
    got = DuckDuckGoLiteEngine.parse(html, "q")
    assert got and got[0].canonical == "https://example.org/p"


def test_a_malformed_payload_is_no_results_not_an_exception() -> None:
    assert WikipediaEngine.parse("not json at all", "q") == []
    assert MarginaliaEngine.parse("<html>", "q") == []
    assert SearxngEngine.parse("", "q") == []


# ----------------------------------------------------------- engine plumbing


def test_an_engine_stamps_every_result_with_its_provenance() -> None:
    payload = json.dumps({"query": {"search": [{"title": "Ada", "snippet": "x"}]}})
    engine = WikipediaEngine(FakeFetcher({"wikipedia.org": ok(payload)}), Cfg())
    got = engine.search("ada", 10, robots=AllowAll())
    assert got[0].acquisition.method is Method.SEARCH
    assert got[0].acquisition.provider == "wikipedia"
    assert got[0].acquisition.query == "ada"


def test_a_challenge_page_is_reported_never_solved() -> None:
    body = "<html><body>Please verify you are human. hCaptcha</body></html>"
    engine = MojeekEngine(FakeFetcher({"mojeek.com": ok(body)}),
                          Cfg(allow_serp_pages=True))
    got = engine.search("q", 10, robots=AllowAll())
    assert got.access.is_refusal
    assert "challenge" in got.describe()


def test_robots_disallow_stops_an_engine_before_it_fetches() -> None:
    robots = ok("User-agent: *\nDisallow: /search\n")
    fetcher = FakeFetcher({"robots.txt": robots,
                           "mojeek.com/search": ok("<a href='https://x.test/'>x</a>")})
    engine = MojeekEngine(fetcher, Cfg(allow_serp_pages=True))
    got = engine.search("q", 10, robots=RobotsCache(fetcher))
    assert got.access.is_refusal
    assert not any("mojeek.com/search" in u for u in fetcher.asked), \
        "a disallowed URL must not be requested at all"


def test_a_missing_robots_file_means_allowed() -> None:
    fetcher = FakeFetcher({})  # everything 404s, including robots.txt
    assert RobotsCache(fetcher).check("https://example.test/x").allowed


def test_an_unreachable_robots_file_is_unknown_not_allowed() -> None:
    fetcher = FakeFetcher({"robots.txt": Response(url="u", status=0,
                                                  error="connection refused")})
    verdict = RobotsCache(fetcher).check("https://example.test/x")
    assert verdict.allowed, "we may still try; the fetcher will find out"
    assert verdict.status == "unknown", "but we must not claim permission"


def test_robots_is_fetched_once_per_host() -> None:
    fetcher = FakeFetcher({"robots.txt": ok("User-agent: *\nAllow: /\n")})
    cache = RobotsCache(fetcher)
    for _ in range(5):
        cache.check("https://example.test/a")
    assert sum("robots.txt" in u for u in fetcher.asked) == 1


def test_a_protected_robots_file_means_the_whole_site_is_off_limits() -> None:
    fetcher = FakeFetcher({"robots.txt": Response(url="u", status=403)})
    assert not RobotsCache(fetcher).check("https://example.test/x").allowed


# ----------------------------------------------------------------- the service


def _service(**cfg) -> tuple[SearchService, FakeFetcher]:
    payload = json.dumps({"query": {"search": [{"title": "Ada", "snippet": "x"}]}})
    fetcher = FakeFetcher({"wikipedia.org": ok(payload)})
    return SearchService(fetcher, Cfg(**cfg), robots=AllowAll()), fetcher


def test_scraping_engines_are_off_unless_the_operator_opts_in() -> None:
    service, _ = _service()
    names = {e.info.name for e in service.available()}
    assert "mojeek" not in names and "ddg-lite" not in names
    assert "wikipedia" in names

    opted_in, _ = _service(allow_serp_pages=True)
    assert "mojeek" in {e.info.name for e in opted_in.available()}


def test_searxng_without_an_instance_reports_why_rather_than_guessing_one() -> None:
    service, _ = _service()
    reasons = dict(service.search("q").unavailable)
    assert "searxng" in reasons and "instance" in reasons["searxng"]


def test_auto_mode_stops_at_the_first_engine_that_answers() -> None:
    service, fetcher = _service()
    outcome = service.search("ada")
    assert outcome.found
    assert outcome.engines_used == ["wikipedia"]


def test_all_mode_asks_every_available_engine() -> None:
    payload = json.dumps({"query": {"search": [{"title": "Ada", "snippet": "x"}]}})
    marg = json.dumps({"results": [{"url": "https://m.test/a", "title": "A"}]})
    fetcher = FakeFetcher({"wikipedia.org": ok(payload),
                           "api.marginalia.nu": ok(marg)})
    service = SearchService(fetcher, Cfg(), robots=AllowAll(), mode="all")
    outcome = service.search("ada")
    assert set(outcome.engines_used) == {"wikipedia", "marginalia"}


def test_api_mode_refuses_result_page_engines_even_when_enabled() -> None:
    service = SearchService(FakeFetcher(), Cfg(allow_serp_pages=True),
                            robots=AllowAll(), mode="api")
    reasons = dict(service.search("q").unavailable)
    assert "api-only" in reasons.get("mojeek", "")


def test_one_engine_failing_does_not_end_the_search() -> None:
    class Exploding(FakeFetcher):
        def get(self, url, **kw):
            if "marginalia" in url:
                raise RuntimeError("socket gone")
            return super().get(url, **kw)

    payload = json.dumps({"query": {"search": [{"title": "Ada", "snippet": "x"}]}})
    fetcher = Exploding({"wikipedia.org": ok(payload)})
    service = SearchService(fetcher, Cfg(), robots=AllowAll(), mode="all")
    outcome = service.search("ada")
    assert outcome.found and "wikipedia" in outcome.engines_used
    assert any(a["outcome"] == "error" for a in outcome.attempts)


def test_a_rate_limited_engine_is_benched_for_the_rest_of_the_run() -> None:
    fetcher = FakeFetcher({"wikipedia.org": Response(url="u", status=429)})
    health = ProviderHealth()
    service = SearchService(fetcher, Cfg(), robots=AllowAll(), health=health)
    service.search("first")
    assert health.health("wikipedia") is Health.RATE_LIMITED
    reasons = dict(service.search("second").unavailable)
    assert "wikipedia" in reasons


# -------------------------------------------------------------- name handling


def test_name_forms_rearrange_and_never_invent() -> None:
    forms = {f.text for f in name_forms("John Smith")}
    assert "John Smith" in forms
    assert "Smith, John" in forms
    assert not any("A." in f for f in forms), \
        "a middle initial nobody supplied is a different person's name"


def test_a_middle_name_produces_its_initial_but_only_when_it_exists() -> None:
    forms = {f.text for f in name_forms("John Adam Smith")}
    assert "John A. Smith" in forms
    assert "John Smith" in forms


def test_a_surname_particle_is_not_treated_as_a_middle_name() -> None:
    forms = {f.text for f in name_forms("Ludwig van Beethoven")}
    assert "Ludwig van Beethoven" in forms
    assert "Ludwig v. Beethoven" not in forms
    assert "LBeethoven" in forms, "the run-together form drops the particle"


def test_a_single_word_name_is_handled_as_a_partial() -> None:
    forms = name_forms("Prince")
    assert len(forms) == 1 and forms[0].kind == "partial"


def test_a_common_surname_scores_as_less_identifying() -> None:
    assert name_rarity("John Smith") < name_rarity("Aurelio Kowalczyk")
    assert name_rarity("John Adam Smith") > name_rarity("John Smith")


def test_handle_candidates_are_few_and_obvious() -> None:
    got = handle_candidates("Ada Lovelace")
    assert "adalovelace" in got and "a.lovelace" not in got
    assert len(got) <= 6, "a long handle list finds accounts belonging to nobody"


# ------------------------------------------------------------- query planning


def test_a_bare_common_name_query_is_generated_but_marked_ambiguous() -> None:
    plan = QueryPlanner().plan_person("John Smith")
    bare = [q for q in plan if q.text == '"John Smith"']
    assert bare and bare[0].ambiguous


def test_a_known_fact_outranks_the_bare_name() -> None:
    plan = QueryPlanner().plan_person("John Smith", known={"employer": "Acme"})
    top = plan[0]
    assert "Acme" in top.text
    assert top.value > max(q.value for q in plan if q.text == '"John Smith"')


def test_the_plan_is_bounded_and_never_repeats_itself() -> None:
    planner = QueryPlanner()
    plan = planner.plan_person("Ada Lovelace", limit=5)
    assert len(plan) == 5
    # Asking again continues where the first plan stopped rather than
    # re-issuing it: the budget moves on instead of being spent twice.
    again = planner.plan_person("Ada Lovelace", limit=5)
    assert not ({q.text for q in plan} & {q.text for q in again})

    # And it does run out, rather than inventing filler to reach the limit.
    for _ in range(20):
        planner.plan_person("Ada Lovelace", limit=5)
    assert planner.plan_person("Ada Lovelace", limit=5) == []


def test_queries_degrade_for_an_engine_without_the_operator() -> None:
    plan = QueryPlanner().plan_domain("example.com")
    with_ops = next(q for q in plan if "site" in q.operators)
    degraded = with_ops.for_engine(frozenset())
    assert "site:" not in degraded
    assert with_ops.for_engine(frozenset({"site", "filetype", "inurl", "intitle"}))


def test_a_discovery_produces_follow_ups_tied_to_the_subject() -> None:
    planner = QueryPlanner()
    follow = planner.expand("Acme Corp", "org", subject="Ada Lovelace")
    assert follow, "a discovery must be able to change the plan"
    assert any("Ada Lovelace" in q.text for q in follow), \
        "a query about the discovery alone tells us about the discovery"
    assert all(q.origin.startswith("discovery") for q in follow)


def test_the_planner_demotes_a_category_that_keeps_returning_nothing() -> None:
    planner = QueryPlanner()
    before = planner.weight_of(Category.EVENT)
    for _ in range(3):
        planner.observe(next(q for q in planner.plan_person("A B Cdef")
                             if q.category is Category.EVENT), results=0)
        planner._seen.clear()
    assert planner.weight_of(Category.EVENT) < before


def test_learning_is_clamped_so_one_lucky_query_cannot_take_over() -> None:
    planner = QueryPlanner()
    plan = planner.plan_person("Ada Lovelace")
    q = plan[0]
    for _ in range(50):
        planner.observe(q, results=10, useful=10)
    assert planner.weight_of(q.category) <= q.category.weight * 1.6


def test_an_email_plan_leads_with_the_address_itself() -> None:
    plan = QueryPlanner().plan_email("ada@example.org")
    assert plan[0].text == '"ada@example.org"'
    assert plan[0].value >= max(q.value for q in plan[1:])
