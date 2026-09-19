"""The scan runner.

Takes a target, works out what it is, picks the modules that accept that type,
runs them and collects the results. Optionally follows pivots one level deep so
a single command on a domain also profiles the IP it resolves to.

Three jobs beyond "call every module":

* **Isolation.** A module that raises, hangs on a dead source or returns
  nonsense must not take the other fifteen with it. Every module runs behind a
  boundary that turns any exception into a ``FAILED`` status on that module's
  own result.
* **Honest status.** The engine watches how sources answered each module (via
  :class:`_ModuleHttp`) and records "rate limited" or "blocked" rather than
  letting a refusal look like an empty result.
* **Normalisation.** Output is cleaned and de-duplicated on the way out, so a
  new module gets that for free without writing any of it.

Threading note
--------------

Modules run on their **own** pool, separate from the HTTP pool they fan out
onto. Sharing one pool deadlocks: a module occupies a worker while waiting for
requests that themselves need a free worker, and at ``--concurrency 8`` with
nine modules there is none. Two pools, one rule - the outer pool never does
network work itself.
"""

from __future__ import annotations

import collections
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from .brief import SEEDABLE as SEEDABLE_TYPES
from .config import Config
from .entities import FROM_TARGET_TYPE, TO_TARGET_TYPE, Entity, EntityType
from .graph import EntityGraph, Observation
from .http import AccessStatus, Fetcher, Response
from .logging_config import get_logger
from .models import Investigation, ModuleStatus, ScanResult, TargetType
from .normalizer import DataNormalizer
from .addresses import judge_address
from .opsec import PassiveGuard, PassiveViolation
from .registry import Module, detect_type, select, shape_problem

log = get_logger("engine")

ProgressFn = Callable[[str, str], None]

#: How many entities one expansion round looks at before rescoring. Small on
#: purpose: the whole value of the frontier is that what round N finds changes
#: what round N+1 thinks is worth doing, and a wide round throws that away by
#: committing to an ordering computed before any of it ran.
_ROUND_WIDTH = 4

#: How a source's refusal maps onto the module's overall status.
_REFUSAL_STATUS = {
    AccessStatus.RATE_LIMITED: ModuleStatus.RATE_LIMITED,
    AccessStatus.ACCESS_DENIED: ModuleStatus.BLOCKED,
    AccessStatus.BLOCKED: ModuleStatus.BLOCKED,
    AccessStatus.UNAVAILABLE: ModuleStatus.UNAVAILABLE,
    AccessStatus.HUMAN_ACTION_REQUIRED: ModuleStatus.HUMAN_ACTION,
    # Payment is a kind of refusal we must never render as an empty result:
    # "this source would have answered for money" is information.
    AccessStatus.PAYMENT_REQUIRED: ModuleStatus.BLOCKED,
}


#: Response headers that must not reach the case file. A stored Set-Cookie is a
#: live credential sitting in a database the user will copy between machines and
#: attach to reports; nothing in NOVA reads one back, so it is dropped rather
#: than kept for completeness.
_SECRET_HEADERS = frozenset({"set-cookie", "set-cookie2", "authorization",
                             "proxy-authenticate", "www-authenticate"})


def _safe_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k.lower() not in _SECRET_HEADERS}


class _ModuleHttp:
    """A per-module view of the shared fetcher that remembers how sources replied.

    Modules keep calling ``self.http.get(...)`` exactly as before; this wrapper
    sits in between and counts refusals, which is what lets the report say
    "social: incomplete - rate limited" without every module having to
    implement that bookkeeping itself.
    """

    def __init__(self, fetcher: Fetcher, module: str = "",
                 evidence: Any = None, deadline: float | None = None) -> None:
        self._fetcher = fetcher
        self._lock = threading.Lock()
        self.module = module
        #: Monotonic time after which this module stops making requests.
        #:
        #: A thread cannot be killed, so the module is not interrupted - it is
        #: starved. Past the deadline every request returns "module time limit
        #: reached" without a socket being opened, the module's own loops run
        #: out in milliseconds, and the result degrades with that reason on it.
        #:
        #: This is what stops one slow source holding a scan open. The 481-site
        #: username sweep, doubled by its verification pass and serialised by
        #: per-host rate limiting, could occupy a run for minutes with nothing
        #: on screen - which is indistinguishable from a hang to the person
        #: watching, and was reported as one.
        self.deadline = deadline
        self.starved = 0
        #: Optional :class:`~nova_osint.core.store.EvidenceStore`. When present
        #: every response body is filed by digest, so a finding can be traced
        #: back to the exact bytes it was read from months later.
        self.evidence = evidence
        self.seen: collections.Counter[AccessStatus] = collections.Counter()
        #: One row per request, in order. This is the provenance record; it is
        #: kept even for requests that found nothing, because "we looked and the
        #: source was down" is the fact reports normally lose.
        self.ledger: list[dict[str, Any]] = []

    # -- delegation ---------------------------------------------------------

    def get(self, url: str, **kw: Any) -> Response:
        if self.deadline is not None and time.monotonic() > self.deadline:
            with self._lock:
                self.starved += 1
            return Response(url=url, status=0,
                            error="module time limit reached")
        resp = self._fetcher.get(url, **kw)
        self._record(resp, requested=url)
        return resp

    def head(self, url: str, **kw: Any) -> Response:
        return self.get(url, method="HEAD", **kw)

    def get_json(self, url: str, default: Any = None, **kw: Any) -> Any:
        return self.get(url, **kw).json(default)

    def map(self, fn: Callable[[Any], Any], items: Iterable[Any]) -> list[Any]:
        return self._fetcher.map(fn, items)

    def __getattr__(self, name: str) -> Any:
        # timeout, user_agent, limiter, pool, ... - anything we do not wrap.
        return getattr(self._fetcher, name)

    # -- bookkeeping --------------------------------------------------------

    def _record(self, resp: Response, requested: str | None = None) -> None:
        digest = None
        if self.evidence is not None and resp.body:
            # Outside the lock: hashing and gzipping a megabyte of HTML while
            # holding a lock every module thread wants is how a scan turns
            # serial without anyone noticing.
            digest = self.evidence.put(resp.body)
        with self._lock:
            self.seen[resp.access] += 1
            self.ledger.append({
                # The URL the module asked for, which is what a replay looks up.
                # resp.url is where we ended up: rdap.org redirects to the
                # registry's own server, and keying on the landing URL meant a
                # replay could not find the recording it had just made.
                "at": time.time(), "module": self.module,
                "url": requested or resp.url, "final_url": resp.url,
                "status": resp.status, "access": resp.access.value,
                "bytes": len(resp.body), "elapsed": round(resp.elapsed, 3),
                "digest": digest, "cached": resp.from_cache,
                "headers": _safe_headers(resp.headers),
            })

    @property
    def refusals(self) -> list[tuple[AccessStatus, int]]:
        """Refusal kinds seen, worst first."""
        order = [AccessStatus.RATE_LIMITED, AccessStatus.ACCESS_DENIED,
                 AccessStatus.BLOCKED, AccessStatus.UNAVAILABLE]
        return [(kind, self.seen[kind]) for kind in order if self.seen[kind]]

    @property
    def answered(self) -> int:
        return self.seen[AccessStatus.OK] + self.seen[AccessStatus.NOT_FOUND]


def work_key(ent: Entity) -> str:
    """What a module would actually be *asked about* if given this entity.

    A site's front page and the site are one subject. ``https://example.com``
    and ``example.com`` produce different entity ids - correctly, they are
    different kinds of thing - but ``dns``, ``mailsec``, ``whois``,
    ``subdomains``, ``wayback``, ``headers``, ``trackers`` and ``fingerprint``
    ask the identical question of both and spend the requests twice. One real
    scan ran seventy modules where forty would have done, and half of the
    duplication was this.

    A URL with a *path* is not collapsed: ``https://example.com/report.pdf``
    is a document, and the document module must still get it.
    """
    if ent.etype is EntityType.URL:
        parts = urllib.parse.urlsplit(ent.value)
        if parts.path.strip("/") or parts.query:
            return ent.eid
        host = (parts.hostname or "").casefold()
        return f"site:{host}" if host else ent.eid
    if ent.etype in (EntityType.HOST, EntityType.DOMAIN):
        return f"site:{ent.value.casefold()}"
    return ent.eid


def pivot_refusal(target: str, ttype: TargetType) -> str:
    """Why this lead is not worth a lookup, or ``""`` if it is.

    One place, consulted by both expansion paths - the frontier walk that
    ``nova investigate`` uses and the flat ``follow_pivots`` the desktop app's
    "Follow pivots" checkbox runs. A rule enforced in one of the two is a rule
    that holds until somebody clicks the other one.
    """
    if ttype is TargetType.EMAIL:
        verdict = judge_address(target)
        if not verdict.expandable:
            return verdict.reason
    return ""


def entity_for(target: str, ttype: TargetType) -> Entity | None:
    """The graph node a user-typed target corresponds to."""
    etype = FROM_TARGET_TYPE.get(ttype, EntityType.UNKNOWN)
    if etype is EntityType.UNKNOWN:
        return None
    return Entity.make(etype, target)


@dataclass
class Budget:
    """What an expansion is allowed to spend.

    Four limits rather than one, because each bounds a different way for a walk
    to run away. ``max_depth`` bounds how far from the target we drift;
    ``min_score`` bounds how weakly-evidenced a lead can be and still get
    looked at; ``max_entities`` bounds a graph that is broad rather than deep -
    the normal shape for a domain with a thousand certificate names, and the one
    a depth limit alone does nothing about; ``max_seconds`` bounds the thing the
    user actually feels.

    Whichever binds first wins, and :attr:`Expansion.stopped_by` says which did.
    A truncated investigation that does not say it was truncated is the same
    failure as a blocked source reported as an empty result.
    """

    max_depth: int = 2
    min_score: float = 0.05
    max_entities: int = 40
    max_module_runs: int = 60
    max_seconds: float = 300.0
    #: Entity kinds worth spending a lookup on. ``None`` means every kind the
    #: registry has a module for.
    types: frozenset[EntityType] | None = None

    @classmethod
    def quick(cls) -> Budget:
        return cls(max_depth=1, min_score=0.1, max_entities=8, max_module_runs=16,
                   max_seconds=90.0)

    @classmethod
    def deep(cls) -> Budget:
        return cls(max_depth=4, min_score=0.02, max_entities=200,
                   max_module_runs=400, max_seconds=1800.0)


@dataclass
class Expansion:
    """Bookkeeping for one frontier walk, reported alongside the findings."""

    rounds: int = 0
    module_runs: int = 0
    expanded: list[str] = field(default_factory=list)
    #: Which budget limit ended the walk, or "frontier exhausted" if none did.
    stopped_by: str = "frontier exhausted"
    #: Leads that scored well enough but were cut off. Named, not dropped: the
    #: user needs to know the investigation was truncated and where.
    unexplored: list[tuple[str, float]] = field(default_factory=list)
    #: Leads that were found and deliberately **not** followed because the
    #: evidence for them was too thin.
    #:
    #: These used to disappear. ``frontier(min_score=...)`` filters before the
    #: unexplored list is built, so a scan of a common name would find five
    #: accounts sharing the display name, decline to follow any of them - which
    #: is the right call, following them is how these tools assemble a portrait
    #: of five different people - and then report nothing at all about having
    #: made that decision. Declining to follow a lead is a finding.
    below_floor: list[tuple[str, float]] = field(default_factory=list)
    #: Leads that were found and **ruled out**: something argued against them
    #: more strongly than anything argued for them. A different statement from
    #: ``below_floor``, which is "nobody said much either way", and one the
    #: reader needs kept apart - "we checked and it is not him" is a result.
    ruled_out: list[tuple[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rounds": self.rounds, "module_runs": self.module_runs,
            "expanded": self.expanded, "stopped_by": self.stopped_by,
            "unexplored": [{"entity": e, "score": round(s, 4)}
                           for e, s in self.unexplored],
            "below_floor": [{"entity": e, "score": round(s, 4)}
                            for e, s in self.below_floor],
            "ruled_out": [{"entity": e, "reason": r} for e, r in self.ruled_out],
        }


class Engine:
    def __init__(
        self,
        config: Config,
        progress: ProgressFn | None = None,
        normalizer: DataNormalizer | None = None,
        evidence: Any = None,
    ) -> None:
        self.config = config
        #: Optional evidence store; when set, every response body is filed.
        self.evidence = evidence
        self.progress = progress or (lambda module, state: None)
        self.normalizer = normalizer or DataNormalizer()
        kwargs: dict[str, object] = {
            "timeout": config.timeout,
            "concurrency": config.concurrency,
            "per_host_delay": config.per_host_delay,
            "per_host_delay_max": config.per_host_delay_max,
            "retries": config.retries,
            "cache_dir": config.cache_dir,
            "cache_ttl": config.cache_ttl,
            "proxy": config.proxy,
            "verify_tls": config.verify_tls,
        }
        if config.user_agent:
            kwargs["user_agent"] = config.user_agent
        self.http = Fetcher(**kwargs)  # type: ignore[arg-type]
        self._module_pool: ThreadPoolExecutor | None = None
        self._ledger: list[dict[str, Any]] = []
        self._ledger_lock = threading.Lock()

    # --------------------------------------------------------------------- run

    def plan(
        self,
        target: str,
        only: Iterable[str] | None = None,
        exclude: Iterable[str] | None = None,
        target_type: TargetType | None = None,
    ) -> tuple[TargetType, list[Module], list[tuple[str, str]]]:
        """Return ``(type, runnable modules, [(skipped name, reason)])``."""
        ttype = target_type or detect_type(target)
        classes = select(ttype, only, exclude)
        runnable: list[Module] = []
        skipped: list[tuple[str, str]] = []

        # A forced --type that the value cannot satisfy stops the whole run,
        # with the reason on every line. Letting the modules try produces a
        # report full of tracebacks that reads as though the sources broke.
        problem = shape_problem(target, ttype)
        if problem is not None:
            return ttype, [], [(cls.name, problem) for cls in classes]

        for cls in classes:
            if cls.name in self.config.disabled_modules:
                skipped.append((cls.name, "disabled in config.json"))
                continue
            inst = cls(self.http, self.config)
            reason = inst.skip_reason()
            if reason:
                skipped.append((cls.name, reason))
            else:
                runnable.append(inst)
        return ttype, runnable, skipped

    def scan(
        self,
        target: str,
        only: Iterable[str] | None = None,
        exclude: Iterable[str] | None = None,
        target_type: TargetType | None = None,
        on_result: Callable[[ScanResult], None] | None = None,
    ) -> Investigation:
        """Run every applicable module and collect the results.

        ``on_result`` fires as each module finishes, off the calling thread, so
        a UI can stream findings in instead of waiting for the slowest source.
        """
        ttype, modules, skipped = self.plan(target, only, exclude, target_type)
        inv = Investigation(target=target, target_type=ttype, skipped=skipped)
        if not modules:
            log.warning("no runnable modules for %s (%s)", target, ttype.value)
            return inv.finish()

        log.info(
            "scanning %s as %s with %d module(s): %s",
            target, ttype.value, len(modules), ", ".join(m.name for m in modules),
        )
        for name, reason in skipped:
            log.info("skipping %s: %s", name, reason)

        seed = entity_for(target, ttype)
        graph = EntityGraph(seed)
        self._ledger.clear()
        results = self._run_all(modules, target, ttype, on_result, seed)
        inv.results = sorted(results, key=lambda r: r.module)
        for res in results:
            self.merge(graph, res)
        graph.rescore()
        inv.graph = graph
        inv.requests = list(self._ledger)
        inv.finish()
        log.info(
            "scan finished in %.1fs: %d finding(s), %d module(s) incomplete",
            inv.duration, len(inv.findings), len(inv.incomplete),
        )
        return inv

    def _run_all(
        self,
        modules: list[Module],
        target: str,
        ttype: TargetType,
        on_result: Callable[[ScanResult], None] | None,
        subject: Entity | None = None,
    ) -> list[ScanResult]:
        """Run the modules concurrently on a pool of their own."""
        workers = max(1, min(len(modules), self.config.concurrency))
        pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="nova-module")
        self._module_pool = pool
        try:
            return [r for r in pool.map(
                lambda m: self._run_one(m, target, ttype, on_result, subject), modules
            ) if r is not None]
        finally:
            pool.shutdown(wait=False)
            self._module_pool = None

    def _run_one(
        self,
        module: Module,
        target: str,
        ttype: TargetType,
        on_result: Callable[[ScanResult], None] | None,
        subject: Entity | None = None,
    ) -> ScanResult:
        """Run one module behind a hard failure boundary."""
        res = ScanResult(module=module.name, target=target, target_type=ttype)
        res.subject = subject if subject is not None else entity_for(target, ttype)
        limit = float(self.config.option("module_time_limit", 0) or 0)
        recorder = _ModuleHttp(
            self.http, module.name, self.evidence,
            deadline=(time.monotonic() + limit) if limit > 0 else None)
        module.http = recorder  # type: ignore[assignment]
        guard: PassiveGuard | None = None
        if self.config.passive_only and not module.active:
            # --passive already refused to run the modules that declare
            # active = True. This catches the other case: one that forgot to,
            # or grew a request that reaches the target after it was written.
            # A promise a tool cannot check is not worth making.
            guard = PassiveGuard(target)
            module.http = guard.wrap(recorder)  # type: ignore[assignment]
        self.progress(module.name, "start")
        log.debug("module %s started", module.name)
        started = time.monotonic()
        try:
            module.run(target, res)
        except PassiveViolation as exc:
            # Not a module failure - the guard did its job. Reported as a
            # coverage gap so the scan says what it declined to do, rather than
            # producing a quietly smaller result.
            res.degrade(ModuleStatus.SKIPPED, str(exc))
            res.error(str(exc))
            log.warning("passive guard stopped %s: %s", module.name, exc)
        except Exception as exc:  # noqa: BLE001 - the plugin isolation boundary
            # This is the one broad catch in the project and it is the point of
            # the design: a module bug costs that module, not the investigation.
            res.degrade(ModuleStatus.FAILED, f"{type(exc).__name__}: {exc}")
            res.error(f"{type(exc).__name__}: {exc}")
            log.error("module %s failed: %s: %s", module.name, type(exc).__name__, exc)
        res.duration = time.monotonic() - started
        if recorder.starved:
            # Named, never silent: the module stopped early, so its silence is
            # a gap rather than an answer.
            res.degrade(ModuleStatus.PARTIAL,
                        f"stopped after {res.duration:.0f}s at the per-module "
                        f"time limit; {recorder.starved} request(s) not made")
            res.error(f"{module.name} hit the {limit:.0f}s module time limit "
                      f"with {recorder.starved} request(s) still to make")
        if guard is not None and guard.blocked:
            log.info("passive guard blocked %d request(s) from %s",
                     len(guard.blocked), module.name)
        with self._ledger_lock:
            self._ledger.extend(recorder.ledger)

        report = self.normalizer.normalize(res)
        if report.changed:
            log.debug("normaliser on %s: %s", module.name, report.summary())
        self._finalise_status(res, recorder)

        log.info(
            "module %s %s in %.1fs (%d finding(s))",
            module.name, res.status.value, res.duration, len(res.findings),
        )
        self.progress(module.name, "done")
        if on_result is not None:
            try:
                on_result(res)
            except Exception as exc:  # noqa: BLE001 - a consumer bug must not lose the scan
                log.debug("on_result callback raised %s: %s", type(exc).__name__, exc)
        return res

    @staticmethod
    def _finalise_status(res: ScanResult, recorder: _ModuleHttp) -> None:
        """Turn "what the sources did" into the module's reported status."""
        if res.status is ModuleStatus.FAILED:
            return

        refusals = recorder.refusals
        if refusals:
            kind, count = refusals[0]
            reason = f"{count} source request(s) came back '{kind.value}'"
            if res.findings or recorder.answered:
                # Some sources answered, so the module did partial work.
                res.degrade(ModuleStatus.PARTIAL, reason)
            else:
                res.degrade(_REFUSAL_STATUS[kind], reason)
        elif res.errors:
            res.degrade(ModuleStatus.PARTIAL, res.errors[0])

        if res.status is ModuleStatus.SUCCESS and not res.findings:
            res.status = ModuleStatus.EMPTY
            res.status_reason = "ran cleanly, nothing to report"

    # ---------------------------------------------------------------- graph

    @staticmethod
    def merge(graph: EntityGraph, res: ScanResult) -> None:
        """Fold one module's output into the investigation graph.

        Two input shapes, because the module set is being migrated rather than
        rewritten. A module that calls ``result.entity(...)`` says what kind of
        evidence it has and gets scored on it; a module still calling the older
        ``result.pivot(...)`` is not ignored - its pivot becomes a node with a
        deliberately weaker ``pivot-derived`` edge, so old modules keep working
        and new ones are rewarded for being specific.
        """
        for ent in res.nodes:
            graph.add(ent, source=res.module)
        for link in res.links:
            graph.connect(link.src, link.dst, link.label, Observation(
                kind=link.kind, module=link.module or res.module, url=link.url,
                detail=link.detail, evidence=link.evidence, llr=link.llr,
                observed_at=link.observed_at, group=link.group,
                # Stamped here rather than read from a clock inside the graph:
                # the pair is what ``age_days`` means, both are stored, and a
                # case reopened next year rebuilds to the identical scores.
                recorded_at=res.started_at if link.observed_at else None,
            ))
        if res.subject is None:
            return
        # A module that has migrated emits both an entity and, for
        # compatibility, a Pivot for the same thing. Drawing the weak
        # pivot-derived edge beside the typed one would add a second, worse
        # observation to the same pair and drag its score down.
        typed = {e.eid for e in res.nodes}
        for p in res.pivots:
            etype = FROM_TARGET_TYPE.get(p.target_type, EntityType.UNKNOWN)
            found = Entity.make(etype, p.target) if etype is not EntityType.UNKNOWN else None
            if found is None or found.eid == res.subject.eid or found.eid in typed:
                continue
            graph.connect(res.subject, found, "pivot", Observation(
                kind="pivot-derived", module=res.module, detail=p.reason))

    def investigate(
        self,
        target: str,
        only: Iterable[str] | None = None,
        exclude: Iterable[str] | None = None,
        target_type: TargetType | None = None,
        budget: Budget | None = None,
        on_result: Callable[[ScanResult], None] | None = None,
        brief: Any = None,
    ) -> Investigation:
        """Scan the target, then keep going along whatever it connects to.

        The replacement for one flat pass plus a bolted-on pivot step. Each
        round rescores the graph, takes the best-evidenced unexpanded entities
        and runs the modules that accept them; discoveries feed back in and
        change what looks worth doing next. That feedback is the point - a
        second-hop email found through a registry contact outranks a first-hop
        handle found by string similarity, and the budget gets spent
        accordingly.

        The walk stops on whichever budget limit binds first, and says which.

        A ``brief`` turns this from one walk into several converging ones. Every
        identifier in it becomes a seed, all of them expanding into **one**
        graph, so an account reached from an address and the same account
        reached from a name land on one node and their evidence adds. That
        convergence is the entire point: one seed can only produce candidates,
        and it takes a second to tell them apart.
        """
        budget = budget or Budget()
        started = time.monotonic()
        ttype = target_type or detect_type(target)
        seed = entity_for(target, ttype)
        inv = Investigation(target=target, target_type=ttype, brief=brief)
        graph = EntityGraph(seed)
        inv.graph = graph
        expansion = Expansion()
        self._ledger.clear()

        # (module name, subject key) pairs already run. Without this an entity
        # reachable by two paths is scanned twice and the second run silently
        # doubles the request count for no new information.
        done: set[tuple[str, str]] = set()

        queue: list[Entity] = [seed] if seed is not None else []
        if brief is not None:
            # Every identifier in the brief starts the walk, strongest first,
            # so a budget that runs out spends itself on the address lookup
            # rather than on the name search that was always going to return
            # forty people. The seed the user typed keeps its place at the
            # front; the rest are added in the brief's own order.
            seen_eids = {seed.eid} if seed is not None else set()
            for claim in brief.seeds:
                ent = entity_for(claim.value, SEEDABLE_TYPES[claim.kind])
                if ent is None or ent.eid in seen_eids:
                    continue
                seen_eids.add(ent.eid)
                graph.add(ent, score=1.0 if not claim.derived else 0.9)
                queue.append(ent)
            log.info("brief supplies %d seed(s): %s", len(queue),
                     ", ".join(e.value for e in queue))
        if not queue:
            log.warning("cannot expand from %s: unrecognised target type", target)

        while queue:
            expansion.rounds += 1
            for ent in queue:
                if graph.seed is None:
                    graph.seed = ent.eid
                stop = self._budget_stop(budget, expansion, started)
                if stop:
                    expansion.stopped_by = stop
                    break
                results = self._expand_one(ent, only, exclude, done, inv, on_result)
                expansion.module_runs += len(results)
                expansion.expanded.append(ent.eid)
                node = graph.nodes.get(ent.eid)
                if node is not None:
                    node.expanded = True
                for res in results:
                    self.merge(graph, res)
            if expansion.stopped_by != "frontier exhausted":
                break

            graph.rescore()
            if len(graph) >= budget.max_entities:
                expansion.stopped_by = f"entity cap ({budget.max_entities})"
                break
            nxt = graph.frontier(min_score=budget.min_score,
                                 max_depth=budget.max_depth, types=budget.types)
            queue = [n.entity for n in nxt[:_ROUND_WIDTH]]
            for n in nxt[_ROUND_WIDTH:]:
                expansion.unexplored.append((n.entity.eid, n.score))

        graph.rescore()
        # Leads that were good enough but never reached. Reported rather than
        # dropped, so a truncated investigation reads as truncated.
        for n in graph.frontier(min_score=budget.min_score, max_depth=budget.max_depth,
                                types=budget.types):
            if n.entity.eid not in expansion.expanded:
                expansion.unexplored.append((n.entity.eid, n.score))
        seen: set[str] = set()
        expansion.unexplored = [
            (eid, score) for eid, score in
            sorted(expansion.unexplored, key=lambda p: -p[1])
            if not (eid in seen or seen.add(eid))
        ]

        # Everything that *was* discovered and deliberately not pursued. The
        # floor is a judgement the report has to show its working for.
        expandable = set(TO_TARGET_TYPE)
        below = [
            (node.entity.eid, node.score)
            for node in graph.nodes.values()
            if not node.expanded
            and node.entity.etype in expandable
            and node.entity.eid not in seen
            and node.entity.eid != (graph.seed or "")
            and 0.0 < node.score < budget.min_score
        ]
        expansion.below_floor = sorted(below, key=lambda p: -p[1])[:25]

        # Leads the evidence argued against. Named rather than dropped: a lead
        # that was checked and rejected is a different fact from a lead that
        # was never reached, and a report that shows neither reads as a report
        # that never looked.
        expansion.ruled_out = [
            (node.entity.eid,
             self._objection(graph, node.entity.eid) or "evidence against it "
             "outweighed the evidence for it")
            for node in graph.contradicted()[:25]
        ]

        inv.results.sort(key=lambda r: (r.target, r.module))
        inv.requests = list(self._ledger)
        inv.expansion = expansion
        if brief is not None:
            from .identity import resolve

            inv.resolution = resolve(inv, brief)
        inv.finish()
        log.info(
            "investigation finished in %.1fs: %d entities, %d edges, %d finding(s), "
            "stopped by %s",
            inv.duration, len(graph), len(graph.edges), len(inv.findings),
            expansion.stopped_by,
        )
        return inv

    @staticmethod
    def _objection(graph: EntityGraph, eid: str) -> str:
        """The single strongest reason the graph gave for rejecting a lead."""
        worst, reason = 0.0, ""
        for edge in graph.edges_of(eid):
            for ob in edge.observations:
                if ob.strength < worst:
                    worst = ob.strength
                    reason = f"{ob.kind} ({ob.module})"
                    if ob.detail:
                        reason += f": {ob.detail}"
        return reason

    @staticmethod
    def _budget_stop(budget: Budget, expansion: Expansion, started: float) -> str:
        if expansion.module_runs >= budget.max_module_runs:
            return f"module-run cap ({budget.max_module_runs})"
        elapsed = time.monotonic() - started
        if elapsed >= budget.max_seconds:
            return f"time limit ({budget.max_seconds:.0f}s)"
        return ""

    def _expand_one(
        self,
        ent: Entity,
        only: Iterable[str] | None,
        exclude: Iterable[str] | None,
        done: set[tuple[str, str]],
        inv: Investigation,
        on_result: Callable[[ScanResult], None] | None,
    ) -> list[ScanResult]:
        """Run every applicable module against one entity."""
        ttype = TO_TARGET_TYPE.get(ent.etype)
        if ttype is None:
            return []
        # Same gate as follow_pivots, so the rule does not depend on which
        # path the operator took to get here.
        skip = pivot_refusal(ent.value, ttype)
        if skip:
            log.info("not expanding %s: %s", ent.eid, skip)
            if not any(e == ent.eid for e, _ in inv.not_followed):
                inv.not_followed.append((ent.eid, skip))
            return []
        _, modules, skipped = self.plan(ent.value, only, exclude, ttype)
        key = work_key(ent)
        modules = [m for m in modules if (m.name, key) not in done]
        for m in modules:
            done.add((m.name, key))
        # Skips are recorded once, for the seed. Repeating "virustotal needs a
        # key" for every entity in a forty-node graph buries the report.
        if not inv.skipped:
            inv.skipped = skipped
        if not modules:
            return []
        log.info("expanding %s with %d module(s)", ent.eid, len(modules))
        self.progress(f"expand:{ent.value}", "start")
        results = self._run_all(modules, ent.value, ttype, on_result, ent)
        self.progress(f"expand:{ent.value}", "done")
        inv.results.extend(results)
        return results

    def follow_pivots(
        self,
        inv: Investigation,
        limit: int = 5,
        types: set[TargetType] | None = None,
    ) -> list[Investigation]:
        """Scan the most interesting discovered targets, one level deep.

        The filter runs *before* the limit, not after. Otherwise two robots at
        the front of the queue consume two of the five slots and the real leads
        behind them are never reached - which is precisely what happened on the
        run this was written for: of four email pivots costing about sixty
        seconds each, ``unorfl@users.noreply.github.com`` is an alias only
        GitHub has heard of and ``action@github.com`` is GitHub Actions signing
        its own commits.
        """
        types = types or {TargetType.IP, TargetType.EMAIL, TargetType.USERNAME}
        wanted = [p for p in inv.pivots if p.target_type in types]
        queue: list[Any] = []
        for p in wanted:
            skip = pivot_refusal(p.target, p.target_type)
            if skip:
                log.info("not following %s: %s", p.target, skip)
                inv.not_followed.append((p.target, skip))
                continue
            queue.append(p)

        out = []
        for p in queue[:limit]:
            log.info("following pivot %s (%s)", p.target, p.target_type.value)
            self.progress(f"pivot:{p.target}", "start")
            out.append(self.scan(p.target, target_type=p.target_type))
            self.progress(f"pivot:{p.target}", "done")
        return out

    def close(self) -> None:
        if self._module_pool is not None:
            self._module_pool.shutdown(wait=False, cancel_futures=True)
        self.http.close()

    def __enter__(self) -> Engine:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
