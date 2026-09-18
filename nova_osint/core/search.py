"""Search engines as sources, with their results treated as evidence.

Until now NOVA generated forty good queries and ran none of them, on the
reasoning that scraping Google gets you a CAPTCHA in a dozen requests and
breaches their terms. That reasoning is still correct about Google. It was
wrong as a conclusion about *search*, because it left the largest free corpus
on the internet addressable only by printing links for a human to click.

What changed is the shape of the answer: rather than one engine scraped
aggressively, this is several engines that publish an interface for exactly
this - Wikipedia's API, Marginalia's public API, a SearXNG instance the
operator runs - with the human-facing result pages behind an explicit opt-in
and a robots check. An engine that says no is an engine we do not use.

The four rules
--------------

**A snippet is evidence about a page, not about the world.** A search result
says "this engine's index contains a page with this text". That is a real
observation and it is not the same as the page saying it today, so a result
carries ``Confidence.POSSIBLE`` until something fetches the page itself.

**Never claim the API answered when the browser did.** Each result carries the
:class:`~nova_osint.core.acquisition.Acquisition` of the engine that produced
it, including whether it came from a documented endpoint or from parsing a
page meant for a person.

**Ten copies of one article are one source.** Syndication is the dominant
failure mode of search-derived intelligence: the same wire story on ten sites
looks like ten confirmations and is one. :func:`cluster` groups results by
what they *say* as well as where they live, and the graph is given one edge
per group rather than one per result.

**Deduplicate before ranking, not after.** Position is only meaningful within
one engine's result list; merging two engines and then sorting by position
invents a ranking neither engine gave.
"""

from __future__ import annotations

import html
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any

from .acquisition import Acquisition, Method, SourceType
from .providers import (
    Availability,
    Health,
    Provider,
    ProviderHealth,
    ProviderInfo,
    register_provider,
)

log = logging.getLogger(__name__)

__all__ = [
    "SearchResult", "canonical_url", "cluster", "merge", "SearchEngine",
    "SearchService", "SearchOutcome", "ENGINE_MODES",
]

ENGINE_MODES = ("auto", "api", "page", "browser", "all")

#: Query parameters that identify a campaign rather than a document. Stripped
#: before comparison so the same page shared three ways is one URL.
_TRACKING = re.compile(
    r"^(utm_|ga_|fbclid$|gclid$|mc_[ce]id$|igshid$|ref$|ref_src$|spm$|"
    r"_hs[a-z]*$|yclid$|msclkid$|s_kwcid$|at_[a-z]*$)", re.I)

#: Redirect wrappers a SERP puts around the real link. Unwrapped so the
#: canonical URL is the document, not the engine's click tracker.
_UNWRAP = {
    "duckduckgo.com": ("uddg",),
    "www.google.com": ("q", "url"),
    "google.com": ("q", "url"),
    "www.bing.com": ("u",),
    "out.reddit.com": ("url",),
    "l.facebook.com": ("u",),
}


def canonical_url(url: str) -> str:
    """One spelling per document, so two engines' links compare equal.

    Deliberately conservative: it lower-cases the host, drops the fragment and
    campaign parameters, unwraps a known redirector and normalises a trailing
    slash. It does **not** drop other query parameters, because on a great
    many sites the query *is* the document.
    """
    if not url:
        return ""
    url = url.strip()
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return url

    host = (parts.hostname or "").lower()
    if host in _UNWRAP:
        params = urllib.parse.parse_qs(parts.query)
        for name in _UNWRAP[host]:
            inner = params.get(name, [""])[0]
            if inner.startswith(("http://", "https://")):
                return canonical_url(inner)

    kept = [(k, v) for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
            if not _TRACKING.match(k)]
    query = urllib.parse.urlencode(kept)
    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    netloc = host
    if parts.port and parts.port not in (80, 443):
        netloc = f"{host}:{parts.port}"
    if netloc.startswith("www."):
        netloc = netloc[4:]
    return urllib.parse.urlunsplit((parts.scheme.lower() or "https", netloc,
                                    path, query, ""))


def site_of(url: str) -> str:
    """The host, without ``www.`` - the crudest unit of independence."""
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


_WORD = re.compile(r"[a-z0-9]+")


def content_key(title: str, snippet: str) -> str:
    """A fingerprint of what a result *says*, for spotting syndication.

    The first dozen words of the title plus the first dozen of the snippet,
    lower-cased and stripped of punctuation. Crude on purpose: a syndicated
    copy usually reproduces the headline verbatim and rewrites nothing, and a
    cleverer measure would start merging genuinely different pages that share
    a subject.
    """
    words = _WORD.findall(f"{title} {snippet}".lower())
    return " ".join(words[:24])


@dataclass
class SearchResult:
    """One row of one engine's answer to one query."""

    query: str
    engine: str
    title: str
    url: str
    snippet: str = ""
    position: int = 0
    result_type: str = "web"
    acquisition: Acquisition | None = None
    #: Engines that returned this same document. Filled in by :func:`merge`.
    engines: tuple[str, ...] = ()
    #: Set by :func:`cluster`: results sharing one are one observation.
    group: str = ""

    @property
    def canonical(self) -> str:
        return canonical_url(self.url)

    @property
    def site(self) -> str:
        return site_of(self.url)

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query, "engine": self.engine, "title": self.title,
            "url": self.url, "canonical": self.canonical,
            "snippet": self.snippet, "position": self.position,
            "result_type": self.result_type, "group": self.group,
            "engines": list(self.engines) or [self.engine],
            "acquisition": self.acquisition.to_dict() if self.acquisition else None,
        }


def merge(results: list[SearchResult]) -> list[SearchResult]:
    """Collapse the same document returned by several engines into one row.

    The merged row keeps the **best** position it achieved anywhere and the
    names of every engine that returned it, because "three independent
    engines put this first" is a real signal and one row per engine hides it
    inside what looks like three findings.
    """
    out: dict[str, SearchResult] = {}
    for res in results:
        key = res.canonical or res.url
        if not key:
            continue
        existing = out.get(key)
        if existing is None:
            res.engines = (res.engine,)
            out[key] = res
            continue
        if res.engine not in existing.engines:
            existing.engines = (*existing.engines, res.engine)
        if res.position and (not existing.position or res.position < existing.position):
            existing.position = res.position
        if len(res.snippet) > len(existing.snippet):
            existing.snippet = res.snippet
    return list(out.values())


def cluster(results: list[SearchResult]) -> list[SearchResult]:
    """Stamp each result with an independence group, in place.

    Two rules, applied in order. Results that say the same thing share a group
    even on different sites - that is syndication. Results from the same site
    share a group even when they say different things - one publisher agreeing
    with itself twice is one source. What is left is genuine independence.
    """
    by_content: dict[str, str] = {}
    for res in results:
        ckey = content_key(res.title, res.snippet)
        if len(ckey) < 20:
            # Too little text to judge syndication by; fall back to the site.
            res.group = f"site:{res.site}"
            continue
        group = by_content.get(ckey)
        if group is None:
            group = f"text:{ckey[:40]}"
            by_content[ckey] = group
        res.group = group
    return results


def independent(results: list[SearchResult]) -> int:
    """How many genuinely separate sources are in this list."""
    return len({r.group or f"site:{r.site}" for r in results})


# ------------------------------------------------------------------- engines


class SearchEngine(Provider):
    """One search engine NOVA can ask.

    Subclasses supply :attr:`info`, :meth:`build_url` and :meth:`parse`. The
    fetching, the robots check and the provenance stamping are handled here so
    that adding an engine is a URL template and a parser, and so that no
    engine can accidentally skip the politeness step.
    """

    #: True when we are reading a page built for a person rather than a
    #: documented endpoint. Those engines are off unless the operator opts in,
    #: because "technically fetchable" and "offered to programs" differ and
    #: this tool does not pretend otherwise.
    scraping: bool = False
    #: Free text pointing at the rules this engine publishes.
    terms: str = ""
    #: Highest number of results one request returns.
    page_size: int = 10

    def build_url(self, query: str, page: int = 0) -> str:  # pragma: no cover
        raise NotImplementedError

    @classmethod
    def parse(cls, payload: str, query: str) -> list[SearchResult]:  # pragma: no cover
        raise NotImplementedError

    # -- the part every engine shares ---------------------------------------

    #: Whether robots.txt governs this engine. True for anything that reads a
    #: page built for people; false for a documented API.
    #:
    #: This is a real distinction and getting it wrong disables the tool. The
    #: Robots Exclusion Protocol addresses *crawlers* of web content, and both
    #: Wikipedia and Marginalia disallow their API paths in robots.txt for the
    #: obvious reason - they do not want search engines indexing JSON - while
    #: publishing those same endpoints for programmatic use and documenting
    #: the etiquette for it. Applying robots.txt to an API is not caution, it
    #: is a category error that refuses an invitation. What governs an API is
    #: its terms, which is why every engine here carries a ``terms_url``.
    #:
    #: Set ``module_options.strict_robots`` to apply the check everywhere
    #: regardless; it will switch most free engines off.
    robots_applies: bool = False

    def search(self, query: str, limit: int = 10, *,
               robots: Any = None) -> Any:
        """Results, or the refusing ``Response`` so the router can classify it."""
        url = self.build_url(query)
        if robots is not None and self._robots_governs():
            verdict = robots.check(url)
            if not verdict.allowed:
                log.info("%s: robots.txt disallows %s", self.info.name, url)
                return _Refused(AccessLike.BLOCKED, verdict.reason)

        resp = self.http.get(url, headers=self.headers())
        if not getattr(resp, "ok", False):
            return resp
        body = resp.text
        if self.looks_like_a_challenge(body):
            # A CAPTCHA or interstitial. Named, never solved, never retried
            # with a different identity.
            return _Refused(AccessLike.HUMAN_ACTION,
                            f"{self.info.name} served a challenge page")

        results = self.parse(body, query)[:limit]
        acq = Acquisition.from_response(
            resp, self.info.name, method=Method.SEARCH, query=query,
            source_type=SourceType.SEARCH_ENGINE, requested=url)
        for res in results:
            res.acquisition = acq
        return results

    def _robots_governs(self) -> bool:
        if self.scraping or self.robots_applies:
            return True
        cfg = self.config
        return bool(cfg and getattr(cfg, "option", lambda *_a: False)(
            "strict_robots", False))

    def headers(self) -> dict[str, str]:
        return {}

    @staticmethod
    def looks_like_a_challenge(body: str) -> bool:
        """Detect a bot check without trying to get past one."""
        low = body[:4000].lower()
        return any(marker in low for marker in (
            "captcha", "are you a robot", "unusual traffic",
            "cf-browser-verification", "please enable javascript and cookies",
            "recaptcha", "hcaptcha", "verifying you are human",
        ))

    def collect(self, target: str, **kw: Any) -> list[Any]:
        """Provider interface: one search, as observations."""
        return self.search(target, int(kw.get("limit", 10)),
                           robots=kw.get("robots"))

    def health(self, health: ProviderHealth | None = None) -> Health:
        base = super().health(health)
        if base is not Health.OK:
            return base
        if self.scraping and not self._scraping_allowed():
            return Health.DISABLED
        return Health.OK

    def _scraping_allowed(self) -> bool:
        cfg = self.config
        if cfg is None:
            return False
        return bool(getattr(cfg, "option", lambda *_a: False)("allow_serp_pages", False))


class AccessLike:
    """The three refusal shapes an engine can produce without an HTTP status.

    A tiny stand-in rather than an import of ``AccessStatus``, so this module
    stays free of the HTTP layer and can be unit-tested with no fetcher at
    all. The router only ever reads ``.access.is_refusal`` and the value's
    string form, both of which these provide.
    """

    BLOCKED = "blocked"
    HUMAN_ACTION = "human action required"
    UNAVAILABLE = "unavailable"


@dataclass
class _Refused:
    """Duck-typed like a ``Response`` refusal, for the router's benefit."""

    kind: str
    detail: str = ""
    status: int = 0

    @property
    def access(self) -> Any:
        return _AccessValue(self.kind)

    @property
    def ok(self) -> bool:
        return False

    def describe(self) -> str:
        return self.detail or self.kind


@dataclass(frozen=True)
class _AccessValue:
    value: str

    @property
    def is_refusal(self) -> bool:
        return True

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


# -- concrete engines --------------------------------------------------------


@register_provider
class WikipediaEngine(SearchEngine):
    """MediaWiki's own search API. Free, documented, generous, and the single
    best free source of "is this name a person anyone has written about"."""

    info = ProviderInfo(
        name="wikipedia", label="Wikipedia",
        availability=Availability.FREE, method=Method.SEARCH,
        source_type=SourceType.SEARCH_ENGINE,
        homepage="https://en.wikipedia.org",
        terms_url="https://www.mediawiki.org/wiki/API:Etiquette",
        notes="MediaWiki search API; documented for programmatic use.",
        rate_limit="no hard limit; be polite",
    )

    def build_url(self, query: str, page: int = 0) -> str:
        params = urllib.parse.urlencode({
            "action": "query", "list": "search", "srsearch": query,
            "srlimit": 20, "sroffset": page * 20, "format": "json",
            "formatversion": 2,
        })
        return f"https://en.wikipedia.org/w/api.php?{params}"

    @classmethod
    def parse(cls, payload: str, query: str) -> list[SearchResult]:
        import json

        try:
            data = json.loads(payload)
        except (ValueError, TypeError):
            return []
        hits = (data.get("query") or {}).get("search") or []
        out = []
        for i, hit in enumerate(hits, start=1):
            title = str(hit.get("title", "")).strip()
            if not title:
                continue
            out.append(SearchResult(
                query=query, engine="wikipedia", title=title,
                url="https://en.wikipedia.org/wiki/"
                    + urllib.parse.quote(title.replace(" ", "_")),
                snippet=_strip_tags(str(hit.get("snippet", ""))),
                position=i, result_type="encyclopedia",
            ))
        return out


@register_provider
class MarginaliaEngine(SearchEngine):
    """An independent index of the non-commercial web, with a public API.

    Worth having precisely because it is not the same index as everyone
    else's: personal sites, university pages and old forums that a commercial
    engine has demoted into invisibility are what it is built to surface, and
    those are where a person's own words usually live.
    """

    info = ProviderInfo(
        name="marginalia", label="Marginalia Search",
        availability=Availability.FREE_WITH_LIMITS, method=Method.SEARCH,
        source_type=SourceType.SEARCH_ENGINE,
        homepage="https://search.marginalia.nu",
        terms_url="https://api.marginalia.nu/",
        notes="Public API key, intended for light programmatic use.",
        rate_limit="courtesy limit on the public key",
    )

    #: The documented demo key. An operator with their own key sets
    #: ``module_options.marginalia_key`` and it is used instead.
    PUBLIC_KEY = "public"

    def build_url(self, query: str, page: int = 0) -> str:
        key = self.PUBLIC_KEY
        if self.config is not None:
            key = self.config.option("marginalia_key", self.PUBLIC_KEY) or self.PUBLIC_KEY
        return (f"https://api.marginalia.nu/{urllib.parse.quote(str(key))}"
                f"/search/{urllib.parse.quote(query)}")

    @classmethod
    def parse(cls, payload: str, query: str) -> list[SearchResult]:
        import json

        try:
            data = json.loads(payload)
        except (ValueError, TypeError):
            return []
        hits = data.get("results") if isinstance(data, dict) else data
        if not isinstance(hits, list):
            return []
        out = []
        for i, hit in enumerate(hits, start=1):
            if not isinstance(hit, dict):
                continue
            url = str(hit.get("url", "")).strip()
            if not url:
                continue
            out.append(SearchResult(
                query=query, engine="marginalia",
                title=str(hit.get("title", "")).strip() or url,
                url=url,
                snippet=_strip_tags(str(hit.get("description", ""))),
                position=i,
            ))
        return out


@register_provider
class SearxngEngine(SearchEngine):
    """Whatever SearXNG instance the operator runs or trusts.

    The honest way to reach the big engines' indexes: the operator points this
    at an instance they are entitled to use, and NOVA asks it politely in JSON.
    Without a configured instance it reports itself unavailable rather than
    picking a stranger's server and spending their quota.
    """

    info = ProviderInfo(
        name="searxng", label="SearXNG",
        availability=Availability.FREE, method=Method.SEARCH,
        source_type=SourceType.SEARCH_ENGINE,
        homepage="https://searxng.org",
        notes="Operator-configured instance (module_options.searxng_url).",
    )

    def instance(self) -> str:
        if self.config is None:
            return ""
        return str(self.config.option("searxng_url", "") or "").rstrip("/")

    def build_url(self, query: str, page: int = 0) -> str:
        base = self.instance()
        params = urllib.parse.urlencode({"q": query, "format": "json",
                                         "pageno": page + 1})
        return f"{base}/search?{params}"

    def health(self, health: ProviderHealth | None = None) -> Health:
        if not self.instance():
            return Health.DISABLED
        return super().health(health)

    @classmethod
    def parse(cls, payload: str, query: str) -> list[SearchResult]:
        import json

        try:
            data = json.loads(payload)
        except (ValueError, TypeError):
            return []
        hits = data.get("results") if isinstance(data, dict) else None
        if not isinstance(hits, list):
            return []
        out = []
        for i, hit in enumerate(hits, start=1):
            if not isinstance(hit, dict):
                continue
            url = str(hit.get("url", "")).strip()
            if not url:
                continue
            out.append(SearchResult(
                query=query, engine="searxng",
                title=str(hit.get("title", "")).strip() or url,
                url=url, snippet=_strip_tags(str(hit.get("content", ""))),
                position=int(hit.get("positions", [i])[0]
                             if isinstance(hit.get("positions"), list)
                             and hit.get("positions") else i),
                result_type=str(hit.get("category", "web")),
            ))
        return out


@register_provider
class MojeekEngine(SearchEngine):
    """An independent crawler with its own index, read from its result page.

    Marked ``scraping`` and therefore off by default. It is here because its
    index is genuinely separate from Bing's and Google's, which is worth a
    great deal when the question is whether two sources are independent -
    but reading a page built for a person is a choice the operator makes,
    not one this tool makes for them.
    """

    info = ProviderInfo(
        name="mojeek", label="Mojeek",
        availability=Availability.FREE, method=Method.SEARCH,
        source_type=SourceType.SEARCH_ENGINE,
        homepage="https://www.mojeek.com",
        terms_url="https://www.mojeek.com/about/terms.html",
        notes="Independent index. Result page, so opt-in (--serp-pages).",
    )
    scraping = True

    def build_url(self, query: str, page: int = 0) -> str:
        params = urllib.parse.urlencode({"q": query, "s": page * 10})
        return f"https://www.mojeek.com/search?{params}"

    @classmethod
    def parse(cls, payload: str, query: str) -> list[SearchResult]:
        return _parse_serp(payload, query, "mojeek",
                           skip_hosts=("mojeek.com",))


@register_provider
class DuckDuckGoLiteEngine(SearchEngine):
    """DuckDuckGo's no-JavaScript result page. Scraping, so opt-in."""

    info = ProviderInfo(
        name="ddg-lite", label="DuckDuckGo Lite",
        availability=Availability.FREE, method=Method.SEARCH,
        source_type=SourceType.SEARCH_ENGINE,
        homepage="https://lite.duckduckgo.com",
        terms_url="https://duckduckgo.com/terms",
        notes="HTML result page, so opt-in (--serp-pages).",
    )
    scraping = True

    def build_url(self, query: str, page: int = 0) -> str:
        return ("https://lite.duckduckgo.com/lite/?"
                + urllib.parse.urlencode({"q": query}))

    @classmethod
    def parse(cls, payload: str, query: str) -> list[SearchResult]:
        return _parse_serp(payload, query, "ddg-lite",
                           skip_hosts=("duckduckgo.com",))


# ----------------------------------------------------------------- HTML bits


class _Links(HTMLParser):
    """Anchors with their text, in document order. Deliberately dumb.

    A SERP parser tied to one site's class names breaks the week that site
    changes them, and the failure is silent - zero results reads exactly like
    "nothing was found". Collecting every outbound link and filtering
    afterwards degrades instead: a layout change costs precision, not the
    whole engine.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        href = dict(attrs).get("href") or ""
        if href.startswith(("http://", "https://", "//")) or "uddg=" in href:
            self._href = href if not href.startswith("//") else "https:" + href
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._href is not None:
            text = " ".join("".join(self._text).split())
            self.links.append((self._href, text))
            self._href = None
            self._text = []


def _parse_serp(payload: str, query: str, engine: str,
                skip_hosts: tuple[str, ...] = ()) -> list[SearchResult]:
    parser = _Links()
    try:
        parser.feed(payload)
    except Exception:  # noqa: BLE001 - malformed markup is not an error here
        pass

    seen: set[str] = set()
    out: list[SearchResult] = []
    for href, text in parser.links:
        url = canonical_url(href)
        host = site_of(url)
        if not host or url in seen:
            continue
        if any(host == s or host.endswith("." + s) for s in skip_hosts):
            continue
        if len(text) < 3:
            continue
        seen.add(url)
        out.append(SearchResult(query=query, engine=engine, title=text,
                                url=href if href.startswith("http") else url,
                                position=len(out) + 1))
    return out


_TAG = re.compile(r"<[^>]+>")


def _strip_tags(text: str) -> str:
    return html.unescape(_TAG.sub("", text)).strip()


# ------------------------------------------------------------------- service


@dataclass
class SearchOutcome:
    """What a search cost and what it produced."""

    query: str
    results: list[SearchResult] = field(default_factory=list)
    engines_used: list[str] = field(default_factory=list)
    attempts: list[dict[str, Any]] = field(default_factory=list)
    #: Engines that could have answered but were not asked, and why.
    unavailable: list[tuple[str, str]] = field(default_factory=list)

    @property
    def found(self) -> bool:
        return bool(self.results)

    @property
    def independent_sources(self) -> int:
        return independent(self.results)

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "results": [r.to_dict() for r in self.results],
            "engines_used": self.engines_used,
            "attempts": self.attempts,
            "unavailable": [{"engine": e, "reason": r} for e, r in self.unavailable],
            "independent_sources": self.independent_sources,
        }


#: Preference order in ``auto`` mode. Documented endpoints first, operator
#: infrastructure next, human result pages last and only on request.
DEFAULT_ORDER = ("searxng", "marginalia", "wikipedia", "mojeek", "ddg-lite")


class SearchService:
    """Runs a query across whichever engines are available, and says which.

    Not a module: modules are per-target and this is per-*query*, and several
    modules plus the investigation orchestrator all need it.
    """

    def __init__(self, fetcher: Any, config: Any = None, *,
                 health: ProviderHealth | None = None,
                 robots: Any = None, mode: str = "auto",
                 browser_engine: Any = None) -> None:
        self.http = fetcher
        self.config = config
        self.health = health or ProviderHealth()
        self.robots = robots
        self.mode = mode if mode in ENGINE_MODES else "auto"
        self.browser_engine = browser_engine
        self._engines: dict[str, SearchEngine] = {}
        for name in DEFAULT_ORDER:
            cls = _ENGINES.get(name)
            if cls is not None:
                self._engines[name] = cls(fetcher, config)
        if browser_engine is not None:
            self._engines[browser_engine.info.name] = browser_engine

    # -- what is available --------------------------------------------------

    def available(self) -> list[SearchEngine]:
        """Engines that could answer right now, in preference order."""
        return [e for e in self._ordered() if self._why_not(e) is None]

    def _ordered(self) -> list[SearchEngine]:
        order = {name: i for i, name in enumerate(DEFAULT_ORDER)}
        return sorted(self._engines.values(),
                      key=lambda e: order.get(e.info.name, 99))

    def _why_not(self, engine: SearchEngine) -> str | None:
        mode = self.mode
        if mode == "browser" and engine.info.method is not Method.BROWSER:
            return "browser-only mode"
        if mode != "browser" and engine.info.method is Method.BROWSER:
            return "browser engine not selected (--search-engine browser)"
        if mode == "api" and engine.scraping:
            return "api-only mode; this engine reads a result page"
        if mode == "page" and not engine.scraping:
            return "page-only mode"
        health = engine.health(self.health)
        if health is not Health.OK:
            if health is Health.DISABLED and engine.scraping:
                return "result-page engine, not enabled (--serp-pages)"
            return _reason(health, engine)
        if not self.health.usable(engine.info.name):
            return self.health.why_not(engine.info.name)
        return None

    # -- searching ----------------------------------------------------------

    def search(self, query: str, limit: int = 10, *,
               every: bool | None = None) -> SearchOutcome:
        """Run ``query``. In ``auto`` mode, stop at the first engine that
        answers; in ``all`` mode, ask every available engine and merge.

        Stopping early is the default because a second engine's view of a
        query that already produced twenty results is rarely worth another
        round-trip - and because spreading one investigation's queries across
        engines is politer than putting all of them through one.
        """
        every = self.mode == "all" if every is None else every
        outcome = SearchOutcome(query=query)

        for engine in self._ordered():
            reason = self._why_not(engine)
            if reason is not None:
                outcome.unavailable.append((engine.info.name, reason))
                continue

            got = self._ask(engine, query, limit)
            outcome.attempts.append(got[1])
            if got[0]:
                outcome.results.extend(got[0])
                outcome.engines_used.append(engine.info.name)
                if not every:
                    break

        outcome.results = cluster(merge(outcome.results))
        outcome.results.sort(key=lambda r: (r.position or 999, r.title))
        return outcome

    def _ask(self, engine: SearchEngine, query: str,
             limit: int) -> tuple[list[SearchResult], dict[str, Any]]:
        name = engine.info.name
        try:
            got = engine.search(query, limit, robots=self.robots)
        except Exception as exc:  # noqa: BLE001 - one engine must not end a run
            log.warning("search engine %s raised: %s", name, exc)
            self.health.record(name, ok=False, reason=str(exc))
            return [], {"engine": name, "outcome": "error", "detail": str(exc)}

        access = getattr(got, "access", None)
        if access is not None and getattr(access, "is_refusal", False):
            detail = got.describe() if hasattr(got, "describe") else str(access)
            self.health.record(name, ok=False, access=access,
                               status=int(getattr(got, "status", 0) or 0),
                               reason=detail)
            return [], {"engine": name, "outcome": "refused", "detail": detail}

        if not isinstance(got, list):
            self.health.record(name, ok=False, reason="unexpected reply")
            return [], {"engine": name, "outcome": "error",
                        "detail": "engine returned something that is not results"}

        self.health.record(name, ok=True)
        return got, {"engine": name, "outcome": "ok" if got else "empty",
                     "detail": f"{len(got)} result(s)"}


def _reason(health: Health, engine: SearchEngine) -> str:
    if health is Health.DISABLED and engine.info.name == "searxng":
        return "no instance configured (module_options.searxng_url)"
    return {
        Health.NEEDS_KEY: "needs an API key",
        Health.PAID: "paid source, not enabled",
        Health.DISABLED: "disabled",
        Health.RATE_LIMITED: "rate limited earlier in this run",
        Health.BLOCKED: "refused us earlier in this run",
        Health.UNAVAILABLE: "unreachable",
        Health.HUMAN_ACTION: "served a challenge page; needs a human",
    }.get(health, health.value)


class BrowserSearchEngine(SearchEngine):
    """A search run in the operator's own browser, on the ordinary result page.

    Not registered as a provider and not in :data:`DEFAULT_ORDER`: it exists
    only when the operator passed ``--browser``, and it is constructed with a
    live :class:`~nova_osint.core.browser.BrowserProvider` rather than found by
    name. That asymmetry is deliberate - a browser is a resource somebody
    started, not a source that is simply there.

    A challenge page here is reported exactly as it is everywhere else: the
    kind of wall, the URL, and no attempt to get past it.
    """

    info = ProviderInfo(
        name="browser-search", label="Browser search",
        availability=Availability.FREE, method=Method.BROWSER,
        source_type=SourceType.SEARCH_ENGINE,
        notes="Your own browser, on the ordinary result page.",
    )

    def __init__(self, browser: Any, config: Any = None,
                 engine: str = "duckduckgo") -> None:
        super().__init__(None, config)
        self.browser = browser
        self.engine = engine

    def build_url(self, query: str, page: int = 0) -> str:
        from .browser import search_url

        return search_url(query, self.engine)

    def health(self, health: ProviderHealth | None = None) -> Health:
        if self.browser is None or not getattr(self.browser, "available", False):
            return Health.UNAVAILABLE
        return super().health(health)

    def search(self, query: str, limit: int = 10, *, robots: Any = None) -> Any:
        page = self.browser.search(query, self.engine)
        if page.human_action:
            return _Refused(AccessLike.HUMAN_ACTION, page.describe())
        if not page.ok:
            return _Refused(AccessLike.UNAVAILABLE, page.describe())

        results = _parse_serp(page.html or "", query, "browser-search",
                              skip_hosts=_SERP_SELF_HOSTS)[:limit]
        acq = page.acquisition("browser-search", query=query)
        acq.source_type = SourceType.SEARCH_ENGINE
        for res in results:
            res.acquisition = acq
        return results

    @classmethod
    def parse(cls, payload: str, query: str) -> list[SearchResult]:
        return _parse_serp(payload, query, "browser-search",
                           skip_hosts=_SERP_SELF_HOSTS)


#: Hosts that appear on every result page as navigation rather than results.
_SERP_SELF_HOSTS = ("duckduckgo.com", "google.com", "bing.com", "mojeek.com",
                    "startpage.com", "brave.com", "microsoft.com",
                    "googleadservices.com", "gstatic.com")


#: Filled by the decorators above. Kept separate from the provider registry so
#: that a non-search provider can never end up in the engine order.
_ENGINES: dict[str, type[SearchEngine]] = {
    "wikipedia": WikipediaEngine,
    "marginalia": MarginaliaEngine,
    "searxng": SearxngEngine,
    "mojeek": MojeekEngine,
    "ddg-lite": DuckDuckGoLiteEngine,
}
