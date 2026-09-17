"""Re-run a saved case's parsers against its stored responses, with no network.

Two jobs, and they are the same mechanism:

**Proving a result.** A finding in a report is a claim. ``nova replay`` takes
the case, feeds every module the exact bytes it was given at the time, and
produces the findings again. If the report says the MX record was X, replay
says so too - from evidence anyone holding the case directory can re-hash. A
result that cannot be reproduced from its own evidence was never a result.

**Catching parser regressions for free.** Every case is a recorded fixture. A
change to a module that quietly stops reading a field shows up as findings that
vanish on replay of a case that used to have them, against real captured
responses rather than a hand-written literal that only contains what the author
already thought of.

The hard rule
-------------

**Replay never touches the network.** Not as a default, not as a fallback when
something is missing - a replay that silently reaches out is worse than no
replay, because it turns "this is reproducible" into a claim that is sometimes
false and never says which time. A URL with no stored response comes back as an
explicit :data:`MISSING` response and is counted, so the report can say how much
of the case was actually re-derivable.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from .config import Config
from .engine import entity_for
from .graph import EntityGraph
from .http import Response
from .logging_config import get_logger
from .models import Investigation, ModuleStatus, ScanResult, TargetType
from .normalizer import DataNormalizer
from .registry import get_module

log = get_logger("replay")

#: The status a request gets when the case has no recording of it. Distinct
#: from a 404: the source may well have answered, we simply did not keep it.
MISSING = 0


class ReplayFetcher:
    """A fetcher that can only answer from the evidence store.

    Deliberately not a subclass of :class:`~nova_osint.core.http.Fetcher`:
    inheriting would mean one forgotten override is a live socket. Everything
    here is implemented from nothing, so the only way to reach the network is to
    add a method that does, on purpose.
    """

    def __init__(self, recordings: dict[str, dict[str, Any]], evidence: Any) -> None:
        self._recordings = recordings
        self._evidence = evidence
        self.served = 0
        self.missing: list[str] = []
        #: Set when a stored body no longer hashes to the digest that names it.
        self.corrupt: list[str] = []
        self.timeout = 0.0
        self.user_agent = "NOVA-OSINT/replay"

    # -- the fetcher surface modules use ------------------------------------

    def get(self, url: str, **kw: Any) -> Response:
        row = self._recordings.get(_key(url))
        if row is None:
            self.missing.append(url)
            return Response(url=url, status=MISSING, error="not recorded in this case")
        body = b""
        digest = row.get("digest")
        if digest:
            body = self._evidence.get(digest) or b""
            if body and not self._evidence.verify(digest):
                # A blob that no longer hashes to its own name is the one thing
                # the evidence store exists to notice. Refuse to parse it.
                self.corrupt.append(digest)
                return Response(url=url, status=MISSING,
                                error=f"evidence {digest[:12]} failed verification")
        self.served += 1
        return Response(
            url=row.get("url", url), status=int(row.get("status") or 0),
            headers=row.get("headers") or {}, body=body,
            elapsed=float(row.get("elapsed") or 0.0), from_cache=True,
        )

    def head(self, url: str, **kw: Any) -> Response:
        return self.get(url, **kw)

    def get_json(self, url: str, default: Any = None, **kw: Any) -> Any:
        return self.get(url, **kw).json(default)

    def map(self, fn: Callable[[Any], Any], items: Iterable[Any]) -> list[Any]:
        # Serial on purpose. There is no I/O to overlap, and a thread pool here
        # would reintroduce non-determinism into the one code path whose whole
        # value is being deterministic.
        return [fn(item) for item in items]

    def close(self) -> None:
        return None


def _key(url: str) -> str:
    """Match recordings by URL, ignoring the trailing-slash difference alone."""
    return url.rstrip("/")


@dataclass
class ReplayReport:
    case_id: str
    target: str
    modules: int = 0
    served: int = 0
    missing: list[str] = field(default_factory=list)
    corrupt: list[str] = field(default_factory=list)
    #: ``{module: (then, now)}`` finding counts, only where they differ.
    drift: dict[str, tuple[int, int]] = field(default_factory=dict)
    reproduced: int = 0
    original: int = 0

    @property
    def clean(self) -> bool:
        """Did every recorded request replay, with no finding drift?"""
        return not self.drift and not self.missing and not self.corrupt

    @property
    def coverage(self) -> float:
        total = self.served + len(self.missing)
        return self.served / total if total else 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "case": self.case_id, "target": self.target, "modules": self.modules,
            "served": self.served, "missing": self.missing, "corrupt": self.corrupt,
            "coverage": round(self.coverage, 3),
            "findings": {"original": self.original, "reproduced": self.reproduced},
            "drift": {m: {"then": a, "now": b} for m, (a, b) in self.drift.items()},
            "clean": self.clean,
        }


def replay(store: Any, case_id: str, config: Config | None = None
           ) -> tuple[Investigation, ReplayReport]:
    """Re-derive a case's findings from its stored evidence. No network.

    Returns the rebuilt investigation and a report on how faithfully it came
    back. The two differ when a module changed, when evidence is missing, or
    when a blob no longer verifies - and the report says which.
    """
    record = store.case(case_id)
    if record is None:
        raise ValueError(f"no such case: {case_id}")
    case_id = record.id
    config = config or Config(cache_dir=None)

    rows = [dict(r) for r in store.requests(case_id)]
    for row in rows:
        row["headers"] = _loads(row.get("headers"))
    by_module: dict[str, dict[str, dict[str, Any]]] = {}
    for row in rows:
        index = by_module.setdefault(row.get("module") or "", {})
        index[_key(row["url"])] = row
        # Also reachable by where it landed, so a module that was changed to
        # request the redirect target directly still replays.
        if row.get("final_url"):
            index.setdefault(_key(row["final_url"]), row)

    original_counts: dict[str, int] = {}
    for f in store.findings(case_id):
        original_counts[f["module"]] = original_counts.get(f["module"], 0) + 1

    ttype = TargetType(record.target_type)
    inv = Investigation(target=record.target, target_type=ttype)
    graph = EntityGraph(entity_for(record.target, ttype))
    report = ReplayReport(case_id=case_id, target=record.target,
                          original=sum(original_counts.values()))
    normalizer = DataNormalizer()

    for module_name, recordings in sorted(by_module.items()):
        cls = get_module(module_name)
        if cls is None:
            log.warning("case %s used module %s, which no longer exists",
                        case_id, module_name)
            continue
        fetcher = ReplayFetcher(recordings, store.evidence)
        module = cls(fetcher, config)  # type: ignore[arg-type]
        res = ScanResult(module=module_name, target=record.target, target_type=ttype)
        res.subject = graph.nodes[graph.seed].entity if graph.seed else None
        started = time.monotonic()
        try:
            module.run(record.target, res)
        except Exception as exc:  # noqa: BLE001 - same isolation boundary as a live scan
            res.degrade(ModuleStatus.FAILED, f"{type(exc).__name__}: {exc}")
            res.error(f"{type(exc).__name__}: {exc}")
            log.error("replay of %s failed: %s: %s", module_name, type(exc).__name__, exc)
        res.duration = time.monotonic() - started
        normalizer.normalize(res)

        report.modules += 1
        report.served += fetcher.served
        report.missing.extend(fetcher.missing)
        report.corrupt.extend(fetcher.corrupt)
        then, now = original_counts.get(module_name, 0), len(res.findings)
        if then != now:
            report.drift[module_name] = (then, now)
        report.reproduced += now

        inv.results.append(res)
        from .engine import Engine

        Engine.merge(graph, res)

    graph.rescore()
    inv.graph = graph
    inv.results.sort(key=lambda r: r.module)
    inv.finish()
    return inv, report


def _loads(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return value
    try:
        out = json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}
    return out if isinstance(out, dict) else {}
