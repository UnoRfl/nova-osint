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
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .config import Config
from .http import AccessStatus, Fetcher, Response
from .logging_config import get_logger
from .models import Investigation, ModuleStatus, ScanResult, TargetType
from .normalizer import DataNormalizer
from .registry import Module, detect_type, select

log = get_logger("engine")

ProgressFn = Callable[[str, str], None]

#: How a source's refusal maps onto the module's overall status.
_REFUSAL_STATUS = {
    AccessStatus.RATE_LIMITED: ModuleStatus.RATE_LIMITED,
    AccessStatus.ACCESS_DENIED: ModuleStatus.BLOCKED,
    AccessStatus.BLOCKED: ModuleStatus.BLOCKED,
    AccessStatus.UNAVAILABLE: ModuleStatus.UNAVAILABLE,
}


class _ModuleHttp:
    """A per-module view of the shared fetcher that remembers how sources replied.

    Modules keep calling ``self.http.get(...)`` exactly as before; this wrapper
    sits in between and counts refusals, which is what lets the report say
    "social: incomplete - rate limited" without every module having to
    implement that bookkeeping itself.
    """

    def __init__(self, fetcher: Fetcher) -> None:
        self._fetcher = fetcher
        self._lock = threading.Lock()
        self.seen: collections.Counter[AccessStatus] = collections.Counter()

    # -- delegation ---------------------------------------------------------

    def get(self, url: str, **kw: Any) -> Response:
        resp = self._fetcher.get(url, **kw)
        self._record(resp)
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

    def _record(self, resp: Response) -> None:
        with self._lock:
            self.seen[resp.access] += 1

    @property
    def refusals(self) -> list[tuple[AccessStatus, int]]:
        """Refusal kinds seen, worst first."""
        order = [AccessStatus.RATE_LIMITED, AccessStatus.ACCESS_DENIED,
                 AccessStatus.BLOCKED, AccessStatus.UNAVAILABLE]
        return [(kind, self.seen[kind]) for kind in order if self.seen[kind]]

    @property
    def answered(self) -> int:
        return self.seen[AccessStatus.OK] + self.seen[AccessStatus.NOT_FOUND]


class Engine:
    def __init__(
        self,
        config: Config,
        progress: ProgressFn | None = None,
        normalizer: DataNormalizer | None = None,
    ) -> None:
        self.config = config
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

        results = self._run_all(modules, target, ttype, on_result)
        inv.results = sorted(results, key=lambda r: r.module)
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
    ) -> list[ScanResult]:
        """Run the modules concurrently on a pool of their own."""
        workers = max(1, min(len(modules), self.config.concurrency))
        pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="nova-module")
        self._module_pool = pool
        try:
            return [r for r in pool.map(
                lambda m: self._run_one(m, target, ttype, on_result), modules
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
    ) -> ScanResult:
        """Run one module behind a hard failure boundary."""
        res = ScanResult(module=module.name, target=target, target_type=ttype)
        recorder = _ModuleHttp(self.http)
        module.http = recorder  # type: ignore[assignment]
        self.progress(module.name, "start")
        log.debug("module %s started", module.name)
        started = time.monotonic()
        try:
            module.run(target, res)
        except Exception as exc:  # noqa: BLE001 - the plugin isolation boundary
            # This is the one broad catch in the project and it is the point of
            # the design: a module bug costs that module, not the investigation.
            res.degrade(ModuleStatus.FAILED, f"{type(exc).__name__}: {exc}")
            res.error(f"{type(exc).__name__}: {exc}")
            log.error("module %s failed: %s: %s", module.name, type(exc).__name__, exc)
        res.duration = time.monotonic() - started

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

    def follow_pivots(
        self,
        inv: Investigation,
        limit: int = 5,
        types: set[TargetType] | None = None,
    ) -> list[Investigation]:
        """Scan the most interesting discovered targets, one level deep."""
        types = types or {TargetType.IP, TargetType.EMAIL, TargetType.USERNAME}
        queue = [p for p in inv.pivots if p.target_type in types][:limit]
        out = []
        for p in queue:
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
