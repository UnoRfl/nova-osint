"""The free-first ladder: try the cheapest thing that could answer, then the
next, and record which rung actually did.

The problem this solves is not "which source has the data". It is that a
source being unavailable is, in every tool of this kind, indistinguishable in
the output from the data not existing. NOVA already fixed that for modules
(``ModuleStatus``) and for single requests (``AccessStatus``). The router
fixes it for a *need*: "the subject's public repositories" is a question that
four different rungs could answer, and the report should say which one did and
what happened to the ones above it.

The ladder
----------

```
LOCAL  → already computed, or derivable without a socket
CACHE  → NOVA's own on-disk copy, still inside its TTL
STORE  → an earlier case that saw this exact thing
API    → a documented machine endpoint
PAGE   → the public web page behind it
SEARCH → a search engine's index of that page
BROWSER→ the operator's own browser, driven visibly
         ↓
NOT AVAILABLE - named, with every attempt and its reason
```

The three rules
---------------

**Never terminate the investigation because a rung failed.** :meth:`acquire`
has no failure path that raises. Exhausting the ladder is an ordinary result
with ``found=False`` and a reason per rung, and the walk carries on to the
next need. One dead provider must never be able to end a run.

**A paid rung is skipped, not attempted and not hidden.** It appears in the
trail with ``Health.PAID`` so the report can say "there is a source for this,
it costs money, you have not enabled it" - which is a genuinely different
answer from "nothing found" and occasionally the most useful line in a report.

**The trail is the evidence.** Every attempt is recorded whether it succeeded
or not, because "we asked four places and the fourth answered" is the thing a
second investigator needs in order to trust or repeat the result.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .acquisition import LADDER, Acquisition, Method, SourceType
from .providers import Health, ProviderHealth

log = logging.getLogger(__name__)

__all__ = ["Step", "Attempt", "Outcome", "SourceRouter"]


@dataclass
class Step:
    """One rung: a way of answering, and what it costs to try it.

    ``run`` returns whatever the caller wants - a parsed payload, a list of
    search results, a page of text - or ``None`` to mean "this rung could not
    answer". It may also return a ``(value, Acquisition)`` pair when it knows
    its own provenance better than the router does, which the search and
    browser layers both do.
    """

    method: Method
    provider: str
    run: Callable[[], Any]
    source_type: SourceType = SourceType.UNKNOWN
    #: Set when this rung needs something the operator has not provided; the
    #: router records it and moves on without calling ``run``.
    unavailable: str = ""
    health: Health | None = None
    #: A rung that costs money is skipped unless the operator enabled paid use.
    paid: bool = False

    def __post_init__(self) -> None:
        if self.method not in LADDER and self.method is not Method.REPLAY:
            # Not fatal: an exotic method still runs, it just sorts last.
            log.debug("step %s uses off-ladder method %s", self.provider, self.method)


@dataclass
class Attempt:
    """What happened on one rung."""

    method: Method
    provider: str
    outcome: str            # "ok" | "empty" | "skipped" | "refused" | "error"
    detail: str = ""
    health: Health = Health.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return {"method": self.method.value, "provider": self.provider,
                "outcome": self.outcome, "detail": self.detail,
                "health": self.health.value}


@dataclass
class Outcome:
    """The answer, plus the full record of how it was reached."""

    need: str
    value: Any = None
    found: bool = False
    acquisition: Acquisition | None = None
    attempts: list[Attempt] = field(default_factory=list)

    @property
    def method(self) -> Method | None:
        return self.acquisition.method if self.acquisition else None

    @property
    def reason(self) -> str:
        """Why there is no answer, in one line fit for a coverage gap."""
        if self.found:
            return ""
        if not self.attempts:
            return "no source available for this"
        refused = [a for a in self.attempts if a.outcome in ("refused", "error")]
        skipped = [a for a in self.attempts if a.outcome == "skipped"]
        if refused:
            worst = refused[0]
            return f"{worst.provider}: {worst.detail or worst.health.value}"
        if skipped and all(a.outcome in ("skipped", "empty") for a in self.attempts):
            return "; ".join(f"{a.provider}: {a.detail or a.health.value}"
                             for a in skipped[:3])
        return "every source answered, none had it"

    @property
    def unavailable(self) -> bool:
        """True when nothing could even be asked - as opposed to asked and empty.

        This is the distinction the whole file exists for, and the renderers
        key the words CANNOT ACCESS vs NOT FOUND off exactly this property.
        """
        if self.found:
            return False
        return not any(a.outcome == "empty" for a in self.attempts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "need": self.need, "found": self.found,
            "method": self.method.value if self.method else None,
            "acquisition": self.acquisition.to_dict() if self.acquisition else None,
            "attempts": [a.to_dict() for a in self.attempts],
            "reason": self.reason,
        }


def _rung(method: Method) -> int:
    try:
        return LADDER.index(method)
    except ValueError:
        return len(LADDER)


class SourceRouter:
    """Walks a list of :class:`Step` in ladder order and returns the first answer.

    Stateless between calls except for the shared :class:`ProviderHealth`, so
    two threads may route different needs at the same time. The router itself
    opens no sockets - each step does its own work through the fetcher it was
    built with - which keeps the "one socket" rule intact.
    """

    def __init__(self, health: ProviderHealth | None = None, *,
                 allow_browser: bool = False, allow_paid: bool = False,
                 allow_search: bool = True) -> None:
        self.health = health or ProviderHealth()
        self.allow_browser = allow_browser
        self.allow_paid = allow_paid
        self.allow_search = allow_search

    # ------------------------------------------------------------------ main

    def acquire(self, need: str, steps: list[Step], *,
                accept: Callable[[Any], bool] | None = None) -> Outcome:
        """Try each step in ladder order; stop at the first that answers.

        ``accept`` decides whether a returned value counts as an answer. The
        default treats ``None`` and empty containers as "this rung had
        nothing", which is what every caller so far has wanted and keeps a
        provider from ending the ladder by returning an empty list.
        """
        accept = accept or _non_empty
        out = Outcome(need=need)
        for step in sorted(steps, key=lambda s: _rung(s.method)):
            skip = self._skip_reason(step)
            if skip is not None:
                health, detail = skip
                out.attempts.append(Attempt(step.method, step.provider, "skipped",
                                            detail, health))
                continue

            try:
                value = step.run()
            except Exception as exc:  # noqa: BLE001 - a provider bug must not end a run
                log.warning("provider %s raised on %s: %s", step.provider, need, exc)
                self.health.record(step.provider, ok=False, reason=str(exc))
                out.attempts.append(Attempt(step.method, step.provider, "error",
                                            f"{type(exc).__name__}: {exc}",
                                            self.health.health(step.provider)))
                continue

            value, acq = _unpack(value, step)

            # A provider may answer with a refusal object rather than a value;
            # ask the health manager what that means before deciding.
            refusal = _refusal_of(value)
            if refusal is not None:
                self.health.record(step.provider, ok=False, access=refusal,
                                   status=_status_of(value))
                out.attempts.append(Attempt(step.method, step.provider, "refused",
                                            str(refusal),
                                            self.health.health(step.provider)))
                continue

            if not accept(value):
                self.health.record(step.provider, ok=True)
                out.attempts.append(Attempt(step.method, step.provider, "empty",
                                            "answered, nothing to report", Health.OK))
                continue

            self.health.record(step.provider, ok=True)
            out.attempts.append(Attempt(step.method, step.provider, "ok",
                                        "", Health.OK))
            out.value = value
            out.found = True
            out.acquisition = acq or Acquisition(method=step.method,
                                                 provider=step.provider,
                                                 source_type=step.source_type)
            return out

        log.info("no source answered for %s (%d attempt(s))", need, len(out.attempts))
        return out

    # ------------------------------------------------------------- filtering

    def _skip_reason(self, step: Step) -> tuple[Health, str] | None:
        """Why this rung should not even be tried, or None to try it."""
        if step.unavailable:
            return step.health or Health.UNAVAILABLE, step.unavailable
        if step.health is not None and not step.health.usable:
            return step.health, _explain(step.health)
        if step.paid and not self.allow_paid:
            return Health.PAID, "paid source, not enabled (--allow-paid)"
        if step.method is Method.BROWSER and not self.allow_browser:
            return (Health.DISABLED,
                    "browser not enabled for this run (--browser)")
        if step.method is Method.SEARCH and not self.allow_search:
            return Health.DISABLED, "search disabled for this run"
        if not self.health.usable(step.provider):
            return (self.health.health(step.provider),
                    self.health.why_not(step.provider))
        return None

    # ------------------------------------------------------------- reporting

    def availability_rows(self) -> list[tuple[str, str, str]]:
        """``[(provider, health, reason)]`` for the Source Availability table."""
        rows = []
        for name, state in self.health.snapshot().items():
            rows.append((name, state["health"], state["reason"]))
        return rows


def _explain(health: Health) -> str:
    return {
        Health.NEEDS_KEY: "needs an API key",
        Health.PAID: "paid source, not enabled",
        Health.DISABLED: "disabled in configuration",
        Health.RATE_LIMITED: "rate limited, benched for this run",
        Health.BLOCKED: "refused us; not worked around",
        Health.HUMAN_ACTION: "needs a human at the keyboard",
        Health.UNAVAILABLE: "unreachable from this machine",
    }.get(health, health.value)


def _non_empty(value: Any) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, (list, tuple, set, dict, str, bytes)):
        return len(value) > 0
    return True


def _unpack(value: Any, step: Step) -> tuple[Any, Acquisition | None]:
    """Allow a step to return ``(value, Acquisition)`` when it knows better."""
    if (isinstance(value, tuple) and len(value) == 2
            and isinstance(value[1], Acquisition)):
        return value[0], value[1]
    return value, None


def _refusal_of(value: Any) -> Any:
    """An ``AccessStatus`` if this value is really a refusal, else None.

    Kept duck-typed so the router does not import the HTTP layer: anything
    exposing ``.access.is_refusal`` is treated as a response, which covers
    ``Response``, the replay fetcher's responses and the browser's page object
    without any of them having to share a base class.
    """
    access = getattr(value, "access", None)
    if access is not None and getattr(access, "is_refusal", False):
        return access
    return None


def _status_of(value: Any) -> int:
    try:
        return int(getattr(value, "status", 0) or 0)
    except (TypeError, ValueError):
        return 0
