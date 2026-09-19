"""Search results as evidence: the module that actually runs the queries.

`dorks` builds queries and hands them to the analyst. This runs them, against
whichever free engines are reachable, and turns what comes back into findings
and graph entities with their provenance attached.

What a result is worth
----------------------

A search hit is an observation about an *index*, not about the world, and the
gap between those two matters more here than anywhere else in this tool. So:

* Every finding is ``POSSIBLE`` unless the page itself was fetched and read,
  which this module does not do - `documents` and the browser layer do.
* Every finding names its engine and its query, so a reader can rerun it.
* A result that could be about anybody with the subject's name is marked, and
  it never becomes an entity. Turning "a page mentioning John Smith" into a
  node on John Smith's graph is the exact mechanism by which these tools
  assemble a portrait of six different people and present it as one.
* Syndicated copies collapse into one observation. Ten sites carrying one wire
  story are one source, and counting them as ten is how a rumour acquires the
  evidential weight of a fact.

Only sites that *name* themselves are promoted to entities: a result on
github.com/<handle> is a handle, a result on a company domain is a domain.
Everything else stays a finding.
"""

from __future__ import annotations

import re
import urllib.parse

from ..core.entities import EntityType
from ..core.models import Confidence, ModuleStatus, ScanResult, Severity, TargetType
from ..core.queryplan import QueryPlanner
from ..core.registry import Module, register
from ..core.robots import RobotsCache
from ..core.search import SearchService

#: Result hosts whose URL path carries an identifier worth pivoting from.
#: Anything not here contributes a finding and no entity, on purpose.
_HANDLE_HOSTS = {
    "github.com": EntityType.USERNAME,
    "gitlab.com": EntityType.USERNAME,
    "codeberg.org": EntityType.USERNAME,
    "bitbucket.org": EntityType.USERNAME,
    "stackoverflow.com": EntityType.USERNAME,
    "hub.docker.com": EntityType.USERNAME,
    "npmjs.com": EntityType.USERNAME,
    "pypi.org": EntityType.USERNAME,
    "keybase.io": EntityType.USERNAME,
}

_SKIP_PATHS = {"", "about", "search", "explore", "topics", "login", "signup",
               "features", "pricing", "blog", "orgs", "sponsors", "settings",
               "questions", "tags", "users", "help", "legal", "site"}

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


@register
class WebSearchModule(Module):
    """Runs the planned queries and reports what the indexes hold."""

    name = "websearch"
    title = "Free web search"
    description = ("Runs planned queries against free search engines and "
                   "reports the results as evidence, with the engine and "
                   "query attached to every hit.")
    accepts = frozenset({TargetType.PERSON, TargetType.USERNAME,
                         TargetType.EMAIL, TargetType.DOMAIN, TargetType.URL})
    #: Search engines are third parties, not the target's own infrastructure,
    #: so this is passive-safe - the same reasoning the username sweep uses.
    active = False
    slow = True

    #: How many queries one scan may run. Deliberately small: this module is
    #: one of many, and a scan that spends ninety seconds on search has taken
    #: that time from every other source.
    DEFAULT_QUERIES = 6
    RESULTS_PER_QUERY = 10

    def skip_reason(self) -> str | None:
        if str(self.config.option("search_engine", "auto")) == "none":
            return "search disabled for this run (--no-search)"
        return super().skip_reason()

    def run(self, target: str, result: ScanResult) -> None:
        service = self._service()
        if not service.available():
            reasons = "; ".join(
                f"{name}: {why}" for name, why in
                [(e.info.name, service._why_not(e) or "") for e in service._ordered()]
                if why
            )
            result.degrade(ModuleStatus.SKIPPED,
                           "no search engine available - " + (reasons or "none configured"))
            result.error("no search engine available; "
                         "configure module_options.searxng_url or pass --serp-pages")
            return

        queries = self._queries(target, result.target_type)
        if not queries:
            return

        planner = self._planner
        seen_engines: set[str] = set()
        refused = 0

        for query in queries:
            outcome = service.search(query, self.RESULTS_PER_QUERY)
            planner.observe(query, len(outcome.results),
                            useful=sum(1 for r in outcome.results
                                       if not query.ambiguous))
            seen_engines.update(outcome.engines_used)
            refused += sum(1 for a in outcome.attempts
                           if a.get("outcome") in ("refused", "error"))

            if not outcome.results:
                continue
            self._report(query, outcome, result)

        if seen_engines:
            result.add("engines used", sorted(seen_engines), source="websearch",
                       confidence=Confidence.CONFIRMED)
        elif refused:
            result.degrade(ModuleStatus.UNAVAILABLE,
                           "every search engine refused or failed")

    # ------------------------------------------------------------ internals

    def _service(self) -> SearchService:
        mode = str(self.config.option("search_engine", "auto") or "auto")
        robots = None if self.config.option("ignore_robots", False) \
            else RobotsCache(self.http)
        return SearchService(self.http, self.config, mode=mode, robots=robots)

    def _queries(self, target: str, ttype: TargetType) -> list:
        limit = int(self.config.option("search_queries", self.DEFAULT_QUERIES))
        self._planner = QueryPlanner(max_queries=max(1, limit))
        planner = self._planner
        if ttype is TargetType.PERSON:
            known = dict(self.config.option("known_facts", {}) or {})
            return planner.plan_person(target, known=known, limit=limit)
        if ttype is TargetType.USERNAME:
            return planner.plan_username(target, limit=limit)
        if ttype is TargetType.EMAIL:
            return planner.plan_email(target, limit=limit)
        host = urllib.parse.urlsplit(
            target if "//" in target else f"//{target}").hostname or target
        return planner.plan_domain(host, limit=limit)

    def _report(self, query, outcome, result: ScanResult) -> None:
        groups: dict[str, list] = {}
        for res in outcome.results:
            groups.setdefault(res.group or f"site:{res.site}", []).append(res)

        label = f"search: {query.category.label}"
        for group, members in groups.items():
            best = min(members, key=lambda r: r.position or 999)
            # One entry per independence group, naming the copies rather than
            # listing each as its own finding.
            extra = {
                "query": query.text,
                "engines": sorted({e for m in members for e in (m.engines or (m.engine,))}),
                "rationale": query.rationale,
                "origin": query.origin,
                "copies": len(members),
                "group": group,
            }
            if query.ambiguous:
                extra["caution"] = ("this query cannot attribute a hit to the "
                                    "subject; treat as a lead, not a fact")
            if len(members) > 1:
                extra["also_on"] = sorted({m.site for m in members})[:8]

            finding = result.add(
                label,
                f"{best.title} - {best.snippet}".strip(" -") or best.title,
                source="websearch",
                confidence=Confidence.POSSIBLE,
                severity=Severity.INFO if query.ambiguous else Severity.NOTABLE,
                url=best.url,
                extra=extra,
            )
            finding.acquisition = best.acquisition
            if best.acquisition is not None:
                finding.acquisition.query = query.text

            if not query.ambiguous:
                self._promote(best, query, result)

    def _promote(self, res, query, result: ScanResult) -> None:
        """Turn a result into a graph entity, but only where the URL names one.

        The restraint is the point. A hit on a news site mentioning the
        subject's name is not a fact about the subject; a hit on
        ``github.com/<handle>`` is a handle that exists and can be checked.
        Only the second becomes a node, and even then on the weakest evidence
        kind there is, because a search engine's index is not a witness.
        """
        host = res.site
        etype = _HANDLE_HOSTS.get(host)
        if etype is None:
            for known, kind in _HANDLE_HOSTS.items():
                if host.endswith("." + known):
                    etype, host = kind, known
                    break
        if etype is None:
            return

        path = urllib.parse.urlsplit(res.url).path.strip("/").split("/")
        if not path or path[0].lower() in _SKIP_PATHS or len(path[0]) < 2:
            return

        result.entity(
            etype, path[0],
            relation="named-in-search-result",
            evidence="search-result",
            url=res.url,
            detail=f"{res.engine} result for {query.text}",
        )

    # An address printed in a snippet is a genuine observation about the page,
    # so it is reported - but never as the subject's address, because a
    # snippet routinely contains somebody else's contact details.
    @staticmethod
    def _addresses(text: str) -> list[str]:
        return sorted(set(_EMAIL.findall(text)))
