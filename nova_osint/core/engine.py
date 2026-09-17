"""The scan runner.

Takes a target, works out what it is, picks the modules that accept that type,
runs them on the shared thread pool and collects the results. Optionally follows
pivots one level deep so a single command on a domain also profiles the IP it
resolves to.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable

from .config import Config
from .http import Fetcher
from .models import Investigation, ScanResult, TargetType
from .registry import Module, detect_type, select

ProgressFn = Callable[[str, str], None]


class Engine:
    def __init__(self, config: Config, progress: ProgressFn | None = None) -> None:
        self.config = config
        self.progress = progress or (lambda module, state: None)
        kwargs: dict[str, object] = {
            "timeout": config.timeout,
            "concurrency": config.concurrency,
            "per_host_delay": config.per_host_delay,
            "retries": config.retries,
            "cache_dir": config.cache_dir,
            "cache_ttl": config.cache_ttl,
            "proxy": config.proxy,
            "verify_tls": config.verify_tls,
        }
        if config.user_agent:
            kwargs["user_agent"] = config.user_agent
        self.http = Fetcher(**kwargs)  # type: ignore[arg-type]

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
    ) -> Investigation:
        ttype, modules, _ = self.plan(target, only, exclude, target_type)
        inv = Investigation(target=target, target_type=ttype)
        if not modules:
            return inv

        def run_one(module: Module) -> ScanResult:
            res = ScanResult(module=module.name, target=target, target_type=ttype)
            self.progress(module.name, "start")
            started = time.monotonic()
            try:
                module.run(target, res)
            except Exception as e:  # a module bug must not abort the scan
                res.error(f"{type(e).__name__}: {e}")
            res.duration = time.monotonic() - started
            self.progress(module.name, "done")
            return res

        # Modules run concurrently; each one internally fans out on the same
        # pool, which the per-host limiter keeps from turning into a stampede.
        results = self.http.map(run_one, modules)
        inv.results = [r for r in results if r is not None]
        inv.results.sort(key=lambda r: r.module)
        return inv

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
            self.progress(f"pivot:{p.target}", "start")
            out.append(self.scan(p.target, target_type=p.target_type))
            self.progress(f"pivot:{p.target}", "done")
        return out

    def close(self) -> None:
        self.http.close()

    def __enter__(self) -> Engine:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
