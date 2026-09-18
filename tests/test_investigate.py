"""The browser layer and the `nova investigate` orchestration.

No browser is installed in CI and none is started here. The backends are
tested through their honest-failure paths and through a fake that implements
the same six operations, which is the shape every consumer sees anyway.
"""

from __future__ import annotations

import pytest

from nova_osint.core import investigate as inv_mod
from nova_osint.core.acquisition import Method
from nova_osint.core.browser import (
    BrowserOptions,
    BrowserProvider,
    NullBrowser,
    Page,
    available_backends,
    detect_challenge,
    open_browser,
    search_url,
)
from nova_osint.core.engine import Budget
from nova_osint.core.http import AccessStatus
from nova_osint.core.investigate import Stage, investigate, plan_for
from nova_osint.core.models import Investigation, ScanResult, TargetType
from nova_osint.core.queryplan import Category
from nova_osint.core.search import BrowserSearchEngine


class Cfg:
    def __init__(self, **options) -> None:
        self.options = options

    def option(self, name, default=None):
        return self.options.get(name, default)

    def has(self, name):
        return False


class FakeBrowser(BrowserProvider):
    """Implements the six operations without a browser behind them."""

    name = "fake"

    def __init__(self, page: Page | None = None) -> None:
        super().__init__(BrowserOptions())
        self.available = True
        self.page = page or Page(url="https://example.test/", status=200,
                                 title="A page", text="hello",
                                 html="<a href='https://found.test/x'>Found this</a>")
        self.visited: list[str] = []

    def open(self) -> bool:
        return True

    def navigate(self, url: str) -> Page:
        self.visited.append(url)
        page = self.page
        page.url = url
        return page

    def close(self) -> None:
        self.available = False


# ------------------------------------------------------------------- browser


@pytest.mark.parametrize("text,kind", [
    ("Please solve the CAPTCHA to continue", "bot check"),
    ("Checking your browser before you access", "bot check"),
    ("Sign in to continue reading", "login wall"),
    ("Subscribe to read the full article", "paywall"),
    ("Please enable JavaScript and cookies", "consent or script wall"),
    ("An ordinary page about mathematics", ""),
])
def test_a_wall_is_identified_by_kind_not_just_detected(text, kind) -> None:
    assert detect_challenge(text) == kind


def test_a_page_merely_discussing_captchas_is_not_a_challenge() -> None:
    article = ("Our engineering blog post on rate limiting. " + "x" * 6000
               + " we later added a captcha to the signup form.")
    assert detect_challenge(article) == "", \
        "only the top of a page is a wall; the rest is content"


def test_a_challenge_page_becomes_the_human_action_status() -> None:
    page = Page(url="https://x.test/", human_action="bot check")
    assert page.access is AccessStatus.HUMAN_ACTION_REQUIRED
    assert page.access.is_refusal
    assert not page.ok
    assert "open https://x.test/ yourself" in page.describe()


def test_a_page_is_duck_typed_like_a_response() -> None:
    page = Page(url="u", status=200, text="hi")
    assert page.ok and page.access is AccessStatus.OK
    assert page.acquisition("chrome").method is Method.BROWSER


def test_a_failed_page_carries_its_error_not_an_exception() -> None:
    page = Page(url="u", error="TimeoutError: 20s")
    assert not page.ok
    assert page.access is AccessStatus.UNAVAILABLE
    assert "TimeoutError" in page.describe()


def test_with_no_backend_installed_the_null_browser_names_the_url() -> None:
    browser = NullBrowser()
    page = browser.navigate("https://example.test/thing")
    assert not page.ok
    assert page.url == "https://example.test/thing"
    assert "playwright" in page.error, "the fix must be in the message"


def test_open_browser_never_returns_none_and_never_raises(monkeypatch) -> None:
    monkeypatch.setattr("nova_osint.core.browser.PlaywrightBrowser.installed",
                        staticmethod(lambda: False))
    monkeypatch.setattr("nova_osint.core.browser.SeleniumBrowser.installed",
                        staticmethod(lambda: False))
    browser = open_browser()
    assert isinstance(browser, NullBrowser)
    assert available_backends() == []
    browser.close()


def test_a_backend_that_will_not_start_falls_through_to_the_next(monkeypatch) -> None:
    started: list[str] = []

    class Broken:
        def __init__(self, options=None):
            self.name = "broken"

        @staticmethod
        def installed():
            return True

        def open(self):
            started.append("broken")
            return False

        def close(self):
            pass

    monkeypatch.setattr("nova_osint.core.browser.PlaywrightBrowser", Broken)
    monkeypatch.setattr("nova_osint.core.browser.SeleniumBrowser.installed",
                        staticmethod(lambda: False))
    browser = open_browser()
    assert started == ["broken"]
    assert isinstance(browser, NullBrowser)


def test_the_default_profile_is_temporary_and_removed() -> None:
    from pathlib import Path

    browser = BrowserProvider(BrowserOptions())
    path = Path(browser._profile_dir())
    assert path.exists() and "nova-browser-" in path.name
    browser.close()
    assert not path.exists(), "a throwaway profile must not be left behind"


def test_a_named_profile_is_kept() -> None:
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        browser = BrowserProvider(BrowserOptions(profile=tmp))
        assert browser._profile_dir() == tmp
        browser.close()
        assert Path(tmp).exists()


def test_extract_is_pure_so_it_works_on_a_stored_page() -> None:
    page = Page(url="u", final_url="v", title="T", text="body",
                links=[("https://a.test/", "a")])
    got = BrowserProvider().extract(page)
    assert got["title"] == "T" and got["canonical"] == "v"
    assert got["links"] == [("https://a.test/", "a")]


def test_search_url_falls_back_rather_than_failing() -> None:
    assert "duckduckgo.com" in search_url("q", "nonsense-engine")
    assert "mojeek.com" in search_url("q", "mojeek")


# -------------------------------------------------------- browser as a source


def test_the_browser_search_engine_returns_parsed_results() -> None:
    engine = BrowserSearchEngine(FakeBrowser(), Cfg())
    got = engine.search("ada", 10)
    assert got and got[0].url == "https://found.test/x"
    assert got[0].acquisition.method is Method.BROWSER, \
        "a browser result must never be reported as an API result"


def test_the_browser_search_engine_reports_a_wall_without_touching_it() -> None:
    walled = Page(url="https://ddg.test/", human_action="bot check",
                  text="captcha")
    engine = BrowserSearchEngine(FakeBrowser(walled), Cfg())
    got = engine.search("ada", 10)
    assert got.access.is_refusal
    assert "bot check" in got.describe()


def test_the_browser_engine_is_unavailable_once_the_browser_is_closed() -> None:
    from nova_osint.core.providers import Health

    browser = FakeBrowser()
    engine = BrowserSearchEngine(browser, Cfg())
    assert engine.health() is Health.OK
    browser.close()
    assert engine.health() is Health.UNAVAILABLE


def test_serp_navigation_links_are_not_treated_as_results() -> None:
    html = ("<a href='https://duckduckgo.com/settings'>Settings</a>"
            "<a href='https://real.test/page'>A real result</a>")
    got = BrowserSearchEngine.parse(html, "q")
    assert [r.site for r in got] == ["real.test"]


# ------------------------------------------------------------------- planning


def test_the_plan_is_chosen_from_the_target_type() -> None:
    for target, expected in [("Ada Lovelace", TargetType.PERSON),
                             ("ada@example.org", TargetType.EMAIL),
                             ("example.com", TargetType.DOMAIN)]:
        plan, _ = plan_for(target, Cfg())
        assert plan.target_type is expected
        assert plan.queries, f"no queries planned for {expected.value}"


def test_a_brief_makes_the_plan_more_identifying() -> None:
    from nova_osint.core.brief import from_pairs

    brief = from_pairs(["name=Ada Lovelace", "employer=Analytical Engines"])
    with_brief, _ = plan_for("Ada Lovelace", Cfg(), brief=brief)
    without, _ = plan_for("Ada Lovelace", Cfg())
    assert any("Analytical Engines" in q.text for q in with_brief.queries)
    assert with_brief.queries[0].value >= without.queries[0].value


def test_planning_opens_no_socket() -> None:
    # plan_for takes no fetcher at all, which is the structural guarantee -
    # this test exists so that stays true when somebody adds a "smarter" plan.
    import inspect

    assert "fetcher" not in inspect.signature(plan_for).parameters
    assert "http" not in inspect.signature(plan_for).parameters


# --------------------------------------------------------------- the run tree


class StubEngine:
    """An Engine that returns a fixed investigation and opens nothing."""

    def __init__(self, config, evidence=None, **kw) -> None:
        self.config = config
        self.http = object()
        self.closed = False

    def investigate(self, target, only=None, exclude=None, target_type=None,
                    budget=None, brief=None, **kw) -> Investigation:
        res = ScanResult(module="wikidata", target=target,
                         target_type=target_type or TargetType.PERSON)
        res.add("occupation", "mathematician", source="wikidata")
        inv = Investigation(target=target,
                            target_type=target_type or TargetType.PERSON,
                            results=[res])
        inv.skipped = [("securitytrails", "needs $SECURITYTRAILS_API_KEY")]
        return inv.finish()

    def close(self) -> None:
        self.closed = True


@pytest.fixture()
def stub_engine(monkeypatch):
    monkeypatch.setattr(inv_mod, "Engine", StubEngine)
    monkeypatch.setattr(inv_mod, "_search_service", lambda *a, **k: None)
    return StubEngine


def test_an_investigation_runs_every_stage_and_says_how_each_went(stub_engine) -> None:
    report = investigate("Ada Lovelace", Cfg(), budget=Budget.quick())
    names = [s.name for s in report.stages]
    assert names == ["plan", "images", "search", "sources", "expansion",
                     "follow-up", "correlation", "identity"]
    assert all(s.state != "pending" for s in report.stages), \
        "a stage left pending tells the reader nothing about what happened"


def test_a_stage_that_could_not_run_says_so_rather_than_showing_nothing(
        stub_engine) -> None:
    report = investigate("Ada Lovelace", Cfg(search_engine="none"))
    search = next(s for s in report.stages if s.name == "search")
    assert search.state == "unavailable"
    assert search.reason, "an unavailable stage must carry its reason"


def test_without_a_brief_identity_reports_nothing_to_resolve_against(
        stub_engine) -> None:
    report = investigate("Ada Lovelace", Cfg())
    identity = next(s for s in report.stages if s.name == "identity")
    assert identity.state == "unavailable"
    assert "-K" in identity.reason, "it must name the fix"


def test_the_tree_renders_every_stage(stub_engine) -> None:
    tree = investigate("Ada Lovelace", Cfg()).tree()
    assert "Ada Lovelace" in tree
    for name in ("plan", "search", "sources", "expansion", "correlation"):
        assert name in tree


def test_the_engine_is_always_closed_even_when_a_stage_fails(monkeypatch) -> None:
    engines: list[StubEngine] = []

    class Recording(StubEngine):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            engines.append(self)

        def investigate(self, *a, **kw):
            raise RuntimeError("source layer exploded")

    monkeypatch.setattr(inv_mod, "Engine", Recording)
    monkeypatch.setattr(inv_mod, "_search_service", lambda *a, **k: None)
    with pytest.raises(RuntimeError):
        investigate("Ada Lovelace", Cfg())
    assert engines and engines[0].closed, "a failed run must not leak the fetcher"


def test_provider_health_reaches_the_investigation(stub_engine) -> None:
    report = investigate("Ada Lovelace", Cfg())
    assert isinstance(report.investigation.providers, dict)


def test_skipped_sources_survive_into_the_plan(stub_engine) -> None:
    report = investigate("Ada Lovelace", Cfg())
    assert ("securitytrails", "needs $SECURITYTRAILS_API_KEY") in report.plan.skipped


def test_stage_lines_are_readable(stub_engine) -> None:
    stage = Stage("search", "done", count=12)
    assert "search" in stage.line() and "ok" in stage.line()
    unavailable = Stage("images", "unavailable", reason="no Pillow installed")
    assert "no Pillow installed" in unavailable.line()


def test_follow_up_queries_are_tied_to_the_subject() -> None:
    from nova_osint.core.entities import Entity, EntityType
    from nova_osint.core.graph import EntityGraph
    from nova_osint.core.queryplan import QueryPlanner

    org = Entity.make(EntityType.ORG, "Analytical Engines Ltd")
    graph = EntityGraph(org)
    graph.add(org, score=0.9)
    inv = Investigation(target="Ada Lovelace", target_type=TargetType.PERSON)
    inv.graph = graph

    made = inv_mod._follow_up(inv, QueryPlanner(), "Ada Lovelace", rounds=1)
    assert made, "a strong organisation must generate follow-ups"
    assert any("Ada Lovelace" in q.text for q in made)
    assert all(q.origin.startswith("discovery") for q in made)


def test_follow_up_never_chases_the_subject_itself() -> None:
    from nova_osint.core.entities import Entity, EntityType
    from nova_osint.core.graph import EntityGraph
    from nova_osint.core.queryplan import QueryPlanner

    me = Entity.make(EntityType.USERNAME, "adalovelace")
    graph = EntityGraph(me)
    graph.add(me, score=1.0)
    inv = Investigation(target="adalovelace", target_type=TargetType.USERNAME)
    inv.graph = graph
    assert inv_mod._follow_up(inv, QueryPlanner(), "adalovelace", rounds=1) == []


def test_follow_up_is_bounded() -> None:
    from nova_osint.core.entities import Entity, EntityType
    from nova_osint.core.graph import EntityGraph
    from nova_osint.core.queryplan import QueryPlanner

    seed = Entity.make(EntityType.PERSON, "Subject")
    graph = EntityGraph(seed)
    for i in range(40):
        graph.add(Entity.make(EntityType.DOMAIN, f"site{i}.test"), score=0.5)
    inv = Investigation(target="Subject", target_type=TargetType.PERSON)
    inv.graph = graph
    made = inv_mod._follow_up(inv, QueryPlanner(), "Subject", rounds=1)
    assert len(made) <= 6, "a planner that emits one query per discovery is a crawler"


def test_category_weights_are_used_to_order_follow_ups() -> None:
    from nova_osint.core.queryplan import QueryPlanner

    planner = QueryPlanner()
    made = planner.expand("example.com", "domain", subject="Ada Lovelace")
    assert made[0].category in (Category.DOMAIN, Category.INFRASTRUCTURE,
                                Category.DOCUMENT, Category.EXPOSURE)
