"""One command that runs an investigation, and shows its work while it does.

``nova scan`` asks every module that accepts the target and prints what came
back. ``nova investigate`` is the thing an operator actually wants: give it a
name, or an address, or a photograph, and it decides what to ask, asks it,
notices what the answers imply, asks *that*, and stops when the budget or the
evidence runs out.

Almost all of the machinery already existed. ``Engine.investigate`` is a
frontier walk that rescores after every round; ``graph.py`` decides what is
worth expanding; ``identity.py`` ranks candidates against what the operator
already knew. What was missing is the thing at the front: a plan that turns a
*name* - which identifies a set of people, not a person - into questions, and
a loop that feeds the answers back into the plan.

The three rules
---------------

**The tree is the report's skeleton, not decoration.** Every stage shows what
it asked, what answered, and what could not be reached. A progress display
that only shows successes trains the reader to see an empty section as an
absence, which is the one reading this tool must never encourage.

**Discovery changes the plan, or it was not an investigation.** After each
round the strongest new entities generate follow-up queries, and the planner
re-weights categories by what they actually produced. A fixed query list run
to completion is a search script.

**The budget binds, and says which limit bound.** Depth, entities, module
runs, queries and wall-clock are all capped, and whichever ran out first is
named in the output - the same contract ``Expansion`` already had.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .engine import Budget, Engine
from .models import Investigation, TargetType
from .providers import ProviderHealth
from .queryplan import QueryPlanner
from .registry import detect_type
from .robots import RobotsCache
from .search import SearchService

log = logging.getLogger(__name__)

__all__ = ["Stage", "Plan", "InvestigationReport", "investigate", "plan_for"]


@dataclass
class Stage:
    """One line of the live tree: what was attempted and how it went."""

    name: str
    state: str = "pending"      # pending | running | done | empty | unavailable
    detail: str = ""
    count: int = 0
    reason: str = ""

    MARKS = {"pending": "·", "running": "»", "done": "ok",
             "empty": "-", "unavailable": "!"}

    def line(self, width: int = 26) -> str:
        mark = self.MARKS.get(self.state, "?")
        right = self.detail or (f"{self.count} found" if self.count else
                                {"done": "ok", "empty": "nothing found",
                                 "unavailable": self.reason or "could not look",
                                 "running": "…", "pending": ""}.get(self.state, ""))
        return f"{self.name:<{width}} {mark:<3} {right}"

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "state": self.state, "count": self.count,
                "detail": self.detail, "reason": self.reason}


@dataclass
class Plan:
    """What an investigation intends to do, before it does any of it."""

    target: str
    target_type: TargetType
    queries: list[Any] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    budget: Budget = field(default_factory=Budget)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target, "target_type": self.target_type.value,
            "queries": [q.to_dict() for q in self.queries],
            "modules": self.modules,
            "skipped": [{"module": m, "reason": r} for m, r in self.skipped],
        }


@dataclass
class InvestigationReport:
    """The investigation, plus the record of how it was conducted."""

    investigation: Investigation
    plan: Plan
    stages: list[Stage] = field(default_factory=list)
    queries_run: int = 0
    rounds: int = 0
    stopped_by: str = ""
    #: ``imageint.ImageFacts`` for anything the operator handed in.
    images: list[Any] = field(default_factory=list)

    def tree(self) -> str:
        """The live tree, as text. The same shape the GUI renders."""
        lines = ["TARGET", f"└─ {self.plan.target}  ({self.plan.target_type.value})"]
        for i, stage in enumerate(self.stages):
            last = i == len(self.stages) - 1
            lines.append(("   └─ " if last else "   ├─ ") + stage.line())
        if self.stopped_by:
            lines.append(f"      stopped by: {self.stopped_by}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan": self.plan.to_dict(),
            "stages": [s.to_dict() for s in self.stages],
            "queries_run": self.queries_run, "rounds": self.rounds,
            "stopped_by": self.stopped_by,
        }


def plan_for(target: str, config: Any, *, target_type: TargetType | None = None,
             brief: Any = None, max_queries: int = 8) -> tuple[Plan, QueryPlanner]:
    """Decide what to ask before asking any of it.

    Returned separately from the run so the CLI can show the plan, the GUI can
    preview it, and a test can assert what *would* have been asked without a
    socket existing.
    """
    ttype = target_type or detect_type(target)
    planner = QueryPlanner(max_queries=max_queries)
    known = _known_from(brief)

    if ttype is TargetType.PERSON:
        queries = planner.plan_person(target, known=known, limit=max_queries)
    elif ttype is TargetType.USERNAME:
        queries = planner.plan_username(target, limit=max_queries)
    elif ttype is TargetType.EMAIL:
        queries = planner.plan_email(target, limit=max_queries)
    elif ttype in (TargetType.DOMAIN, TargetType.URL):
        queries = planner.plan_domain(target, limit=max_queries)
    else:
        queries = []

    plan = Plan(target=target, target_type=ttype, queries=queries)
    return plan, planner


def _known_from(brief: Any) -> dict[str, Any]:
    """The operator's claims, as plain ``{kind: value}`` for the planner.

    ``Claim.raw`` rather than ``Claim.value``: the canonical form is folded
    for comparison, and a query should carry what the operator actually typed.
    Searching for ``"analytical engines"`` works, but a report showing the
    query the tool ran should show the operator their own words back.
    """
    if brief is None:
        return {}
    out: dict[str, Any] = {}
    for claim in getattr(brief, "claims", []) or []:
        kind = getattr(getattr(claim, "kind", None), "value", None) \
            or str(getattr(claim, "kind", ""))
        value = getattr(claim, "raw", None) or getattr(claim, "value", None)
        if kind and value and kind not in out:
            out[kind] = value
    return out


ProgressFn = Callable[[list[Stage]], None]


def investigate(target: str, config: Any, *, target_type: TargetType | None = None,
                brief: Any = None, budget: Budget | None = None,
                browser: Any = None, evidence: Any = None,
                only: list[str] | None = None, exclude: list[str] | None = None,
                on_progress: ProgressFn | None = None,
                max_queries: int = 8, follow_up_rounds: int = 1,
                images: list[str] | None = None
                ) -> InvestigationReport:
    """Run the whole thing: plan, expand, follow up, resolve.

    The search stage runs *before* the expansion walk on purpose. A name with
    no other identifier gives the frontier nothing to walk from, and search is
    the only thing that can turn it into handles, domains and organisations
    the rest of the engine already knows how to pursue.
    """
    budget = budget or Budget()
    started = time.monotonic()
    plan, planner = plan_for(target, config, target_type=target_type,
                             brief=brief, max_queries=max_queries)

    stages = [
        Stage("plan", "done", f"{len(plan.queries)} quer{'y' if len(plan.queries) == 1 else 'ies'}"),
        Stage("images"),
        Stage("search"),
        Stage("sources"),
        Stage("expansion"),
        Stage("follow-up"),
        Stage("correlation"),
        Stage("identity"),
    ]
    report = InvestigationReport(investigation=Investigation(
        target=target, target_type=plan.target_type), plan=plan, stages=stages)

    def tick() -> None:
        if on_progress is not None:
            on_progress(stages)

    health = ProviderHealth()
    engine = Engine(config, evidence=evidence)
    try:
        by_name = {s.name: s for s in stages}

        # -- images ---------------------------------------------------------
        # Before search, because an image's clues are among the most
        # identifying things an operator can supply: a conference banner turns
        # a bare name into a name and an event.
        image_facts, image_queries = _read_images(images, planner, target,
                                                  by_name["images"])
        report.images = image_facts
        if image_queries:
            plan.queries = plan.queries + image_queries
        tick()

        # -- search ---------------------------------------------------------
        by_name["search"].state = "running"
        tick()
        service = _search_service(engine, config, health, browser)
        hits, discovered = _run_queries(service, planner, plan.queries, report)
        if service is None or not service.available():
            by_name["search"].state = "unavailable"
            by_name["search"].reason = "no search engine enabled for this run"
        elif hits:
            by_name["search"].state = "done"
            by_name["search"].count = hits
        else:
            by_name["search"].state = "empty"
        tick()

        # -- the modules and the frontier walk -------------------------------
        by_name["sources"].state = "running"
        by_name["expansion"].state = "running"
        tick()
        inv = engine.investigate(target, only=only, exclude=exclude,
                                 target_type=plan.target_type, budget=budget,
                                 brief=brief)
        report.investigation = inv
        plan.modules = sorted({r.module for r in inv.results})
        plan.skipped = list(inv.skipped)

        ran = len(inv.results)
        by_name["sources"].state = "done" if ran else "unavailable"
        by_name["sources"].count = ran
        by_name["sources"].detail = f"{ran} source(s), {len(inv.findings)} finding(s)"
        exp = inv.expansion
        report.rounds = getattr(exp, "rounds", 0)
        report.stopped_by = getattr(exp, "stopped_by", "")
        by_name["expansion"].state = "done" if report.rounds else "empty"
        by_name["expansion"].detail = (
            f"{report.rounds} round(s), {len(inv.graph) if inv.graph else 0} entities")
        tick()

        # -- follow-up: what the scan learned changes what is worth asking ---
        by_name["follow-up"].state = "running"
        tick()
        extra = _follow_up(inv, planner, target, follow_up_rounds)
        if extra and service is not None and service.available():
            more, _ = _run_queries(service, planner, extra, report, result_sink=inv)
            by_name["follow-up"].state = "done" if more else "empty"
            by_name["follow-up"].count = more
            by_name["follow-up"].detail = f"{len(extra)} follow-up quer(ies), {more} hit(s)"
        else:
            by_name["follow-up"].state = "empty"
            by_name["follow-up"].detail = "nothing new worth pursuing"
        tick()

        # -- what was learned about connections and identity -----------------
        edges = len(inv.graph.edges) if inv.graph is not None else 0
        by_name["correlation"].state = "done" if edges else "empty"
        by_name["correlation"].count = edges
        by_name["correlation"].detail = f"{edges} graded connection(s)"

        if inv.resolution is not None:
            by_name["identity"].state = "done"
            by_name["identity"].detail = _resolution_line(inv.resolution)
        elif brief is None:
            by_name["identity"].state = "unavailable"
            by_name["identity"].reason = ("nothing to resolve against - add -K "
                                          "facts you already know")
        else:
            by_name["identity"].state = "empty"
        tick()

        inv.providers = health.snapshot()
        report.queries_run = report.queries_run
        if not report.stopped_by:
            report.stopped_by = "frontier exhausted"
        log.info("investigation of %s finished in %.1fs (%d queries, %d rounds)",
                 target, time.monotonic() - started, report.queries_run,
                 report.rounds)
        return report
    finally:
        engine.close()


def _read_images(images: list[str] | None, planner: QueryPlanner, subject: str,
                 stage: Stage) -> tuple[list[Any], list[Any]]:
    """Read every supplied image locally and turn its clues into queries.

    The stage reports the *gaps* as loudly as the findings: an operator who
    supplied a photograph and got no text back needs to know whether the image
    had none or whether no OCR engine is installed, and those are one line
    apart in the output and a world apart in meaning.
    """
    if not images:
        stage.state = "empty"
        stage.detail = "no image supplied"
        return [], []

    from .imageint import analyse, clues_to_queries

    stage.state = "running"
    facts: list[Any] = []
    queries: list[Any] = []
    gaps: set[str] = set()
    for path in images:
        got = analyse(path)
        facts.append(got)
        queries += clues_to_queries(got, planner, subject)
        gaps.update(reason for _, reason in got.gaps)

    clue_count = sum(len(f.clues) for f in facts)
    stage.count = clue_count
    stage.state = "done" if clue_count else "empty"
    stage.detail = (f"{len(facts)} image(s), {clue_count} clue(s), "
                    f"{len(queries)} quer(ies)")
    if gaps:
        stage.reason = "; ".join(sorted(gaps)[:2])
    return facts, queries


def _search_service(engine: Engine, config: Any, health: ProviderHealth,
                    browser: Any) -> SearchService | None:
    mode = str(getattr(config, "option", lambda *_a: "auto")("search_engine", "auto")
               or "auto")
    if mode == "none":
        return None
    robots = RobotsCache(engine.http)
    browser_engine = None
    if browser is not None and getattr(browser, "available", False):
        from .search import BrowserSearchEngine

        browser_engine = BrowserSearchEngine(browser, config)
    return SearchService(engine.http, config, health=health, robots=robots,
                         mode=mode, browser_engine=browser_engine)


def _run_queries(service: SearchService | None, planner: QueryPlanner,
                 queries: list[Any], report: InvestigationReport,
                 result_sink: Any = None) -> tuple[int, list[tuple[str, str]]]:
    """Run a list of queries, feed the planner, and collect what was learned."""
    if service is None or not queries:
        return 0, []
    hits = 0
    discovered: list[tuple[str, str]] = []
    for query in queries:
        outcome = service.search(query)
        report.queries_run += 1
        planner.observe(query, len(outcome.results),
                        useful=0 if query.ambiguous else len(outcome.results))
        hits += len(outcome.results)
        if result_sink is not None:
            result_sink.routes.append({
                "need": f"search: {query.text}",
                "found": bool(outcome.results),
                "reason": "" if outcome.results else "no engine had results",
                "attempts": outcome.attempts,
            })
    return hits, discovered


def _follow_up(inv: Investigation, planner: QueryPlanner, subject: str,
               rounds: int) -> list[Any]:
    """Queries justified by what the scan just found.

    Only the best-evidenced entities are followed, and only kinds that make a
    query meaningful. Following everything turns one investigation into a
    crawl of the internet, and following weak links turns it into a crawl of
    the internet about somebody else.
    """
    if rounds <= 0 or inv.graph is None:
        return []
    interesting = ("org", "domain", "username", "email", "host")
    seen: set[str] = set()
    made: list[Any] = []
    nodes = sorted(inv.graph.nodes.values(), key=lambda n: -getattr(n, "score", 0.0))
    for node in nodes[:12]:
        ent = node.entity
        kind = getattr(ent.etype, "value", str(ent.etype))
        if kind not in interesting:
            continue
        value = str(ent.value)
        if value.casefold() == subject.casefold() or value in seen:
            continue
        seen.add(value)
        made += planner.expand(value, kind, subject=subject)
        if len(made) >= 6:
            break
    return made[:6]


def _resolution_line(resolution: Any) -> str:
    verdict = getattr(getattr(resolution, "verdict", None), "value", "")
    leader = getattr(resolution, "leader", None)
    name = getattr(leader, "label", "") or getattr(leader, "display", "")
    if verdict and name:
        return f"{verdict}: {name}"
    return verdict or "no candidate separated from the rest"
