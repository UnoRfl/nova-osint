"""What a source costs, whether it can answer right now, and how to add one.

Two things live here that used to be scattered or missing.

**What a source costs the operator.** NOVA's promise is that it works with no
paid subscription, and a promise like that is only checkable if every source
declares its own terms in a machine-readable way. :class:`Availability` is
that declaration. It is deliberately not a boolean: "free", "free but rate
limited", "better with a key you can get for nothing", "needs a key only you
can supply" and "costs money" lead to five different pieces of advice, and
collapsing them to `has_key` throws away the four useful ones.

**Whether a source can answer right now.** Before this, a rate-limited source
was rediscovered on every run and every entity: forty modules would each queue
behind the same 429, spend their retries and report the same failure.
:class:`ProviderHealth` remembers, for the length of one investigation, that a
provider asked us to stop - and the rest of the investigation carries on
without it.

The three rules
---------------

**A provider that cannot answer is never silently skipped.** Skipping and
finding nothing are different facts, and this file's whole reason to exist is
that the report must be able to tell them apart. Every skip carries a reason
and a :class:`Health`, and those reach the Source Availability section.

**Paid means off by default, and *stated*.** A `PAID` provider is not
attempted unless the operator turned it on. It is never reported as "no
result"; it is reported as a source that was not bought. The difference
matters to somebody deciding whether the answer they got is the whole answer.

**Health is per investigation, not global and not persisted.** A source that
rate limited us this afternoon may be fine tomorrow, and a cached verdict of
"blocked" that outlives the run that earned it would quietly amputate the
tool. Nothing here is written to disk.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .acquisition import Acquisition, Method, SourceType

__all__ = [
    "Availability", "Health", "ProviderInfo", "ProviderState", "ProviderHealth",
    "Provider", "register_provider", "all_providers", "get_provider",
    "availability_of_key", "key_provider_rows",
]


class Availability(str, Enum):
    """What it costs to use a source, as the operator experiences it."""

    #: No key, no account, no limit worth planning around.
    FREE = "free"
    #: No key, but a published rate limit that shapes how we use it.
    FREE_WITH_LIMITS = "free with limits"
    #: Works without a key; a free key raises the ceiling.
    OPTIONAL_KEY = "optional key"
    #: Does nothing without a key the operator obtains themselves.
    USER_KEY = "user-provided key"
    #: The key costs money. Off unless explicitly enabled.
    PAID = "paid"
    #: Switched off in configuration.
    DISABLED = "disabled"
    #: Exists, but cannot be reached from this machine right now.
    UNAVAILABLE = "unavailable"

    @property
    def is_free(self) -> bool:
        return self in (Availability.FREE, Availability.FREE_WITH_LIMITS,
                        Availability.OPTIONAL_KEY)

    @property
    def needs_operator_action(self) -> bool:
        return self in (Availability.USER_KEY, Availability.PAID)


class Health(str, Enum):
    """Whether a provider can answer, and if not, why not.

    Shares its vocabulary with ``AccessStatus`` and ``ModuleStatus`` on
    purpose: an investigator should not have to learn a third set of words for
    the same five situations.
    """

    UNKNOWN = "unknown"            # never tried
    OK = "ok"
    RATE_LIMITED = "rate limited"
    BLOCKED = "blocked"
    UNAVAILABLE = "unavailable"
    NEEDS_KEY = "needs key"
    PAID = "paid"
    DISABLED = "disabled"
    HUMAN_ACTION = "human action required"

    @property
    def usable(self) -> bool:
        return self in (Health.UNKNOWN, Health.OK)


#: How long a provider stays benched after asking us to slow down. Long enough
#: that the rest of the walk does not keep poking it, short enough that a long
#: investigation gets a second chance at it.
RATE_LIMIT_BACKOFF = 120.0
#: A hard refusal is not a timing problem, so it lasts the whole run.
BLOCK_BACKOFF = 3600.0


@dataclass(frozen=True)
class ProviderInfo:
    """The static declaration a source makes about itself.

    Frozen because this is a statement of terms, not a mutable state; anything
    that changes during a run belongs in :class:`ProviderState`.
    """

    name: str
    label: str
    availability: Availability
    method: Method
    source_type: SourceType = SourceType.UNKNOWN
    #: The key this provider reads, if any - a name in ``config.KEY_INFO``.
    requires_key: str | None = None
    #: Where a human goes to read the rules or get a key.
    terms_url: str = ""
    homepage: str = ""
    #: One line for the source index.
    notes: str = ""
    #: Published limit, free-text, e.g. "4/min, 500/day".
    rate_limit: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "label": self.label,
            "availability": self.availability.value,
            "method": self.method.value,
            "source_type": self.source_type.value,
            "requires_key": self.requires_key,
            "terms_url": self.terms_url, "homepage": self.homepage,
            "notes": self.notes, "rate_limit": self.rate_limit,
        }


@dataclass
class ProviderState:
    """What we have learned about a provider during this run."""

    health: Health = Health.UNKNOWN
    reason: str = ""
    #: Monotonic time before which this provider should not be tried again.
    benched_until: float = 0.0
    attempts: int = 0
    successes: int = 0
    refusals: int = 0
    last_status: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "health": self.health.value, "reason": self.reason,
            "attempts": self.attempts, "successes": self.successes,
            "refusals": self.refusals,
        }


class ProviderHealth:
    """Thread-safe memory of which sources are answering.

    Both NOVA thread pools touch this, so every method takes the lock. The
    lock is held only around dictionary work - never around a request - so it
    cannot become the serialisation point the two-pool design exists to avoid.
    """

    def __init__(self, clock: Any = None) -> None:
        self._states: dict[str, ProviderState] = {}
        self._lock = threading.Lock()
        #: Injectable so the backoff tests do not sleep.
        self._clock = clock or time.monotonic

    # ------------------------------------------------------------- recording

    def record(self, provider: str, *, ok: bool = False, status: int = 0,
               access: Any = None, reason: str = "") -> Health:
        """Fold one outcome into a provider's state and return its new health.

        ``access`` is an :class:`~nova_osint.core.http.AccessStatus`; it is
        taken as ``Any`` to keep this module importable without dragging the
        HTTP layer in, which matters because the GUI's settings window reads
        provider metadata before any fetcher exists.
        """
        value = getattr(access, "value", access)
        with self._lock:
            st = self._states.setdefault(provider, ProviderState())
            st.attempts += 1
            st.last_status = status or st.last_status
            if ok:
                st.successes += 1
                st.health = Health.OK
                st.reason = ""
                st.benched_until = 0.0
                return st.health

            st.refusals += 1
            health, backoff = _health_for(value, status)
            st.health = health
            st.reason = reason or (str(value) if value else "")
            if backoff:
                st.benched_until = self._clock() + backoff
            return health

    def note(self, provider: str, health: Health, reason: str = "",
             backoff: float = 0.0) -> None:
        """State a provider's health directly, for things HTTP cannot express:
        a missing key, a disabled source, a browser awaiting a human."""
        with self._lock:
            st = self._states.setdefault(provider, ProviderState())
            st.health = health
            st.reason = reason
            if backoff:
                st.benched_until = self._clock() + backoff

    # -------------------------------------------------------------- querying

    def state(self, provider: str) -> ProviderState:
        with self._lock:
            return self._states.get(provider, ProviderState())

    def health(self, provider: str) -> Health:
        return self.state(provider).health

    def usable(self, provider: str) -> bool:
        """True when it is worth trying this provider right now."""
        with self._lock:
            st = self._states.get(provider)
            if st is None:
                return True
            if st.benched_until and self._clock() < st.benched_until:
                return False
            if st.benched_until and self._clock() >= st.benched_until:
                # The bench expired. Forget the verdict but keep the counters,
                # so a provider that recovers is not reported as still broken.
                st.benched_until = 0.0
                if st.health in (Health.RATE_LIMITED, Health.UNAVAILABLE):
                    st.health = Health.UNKNOWN
                return True
            return st.health.usable

    def why_not(self, provider: str) -> str:
        st = self.state(provider)
        if st.health.usable:
            return ""
        return st.reason or st.health.value

    def snapshot(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {k: v.to_dict() for k, v in sorted(self._states.items())}

    def clear(self) -> None:
        with self._lock:
            self._states.clear()


def _health_for(access: Any, status: int) -> tuple[Health, float]:
    """Map an access outcome onto a health verdict and a bench period."""
    text = str(access or "").lower()
    if "rate" in text or status == 429:
        return Health.RATE_LIMITED, RATE_LIMIT_BACKOFF
    if "human" in text:
        return Health.HUMAN_ACTION, 0.0
    if "payment" in text or status == 402:
        return Health.PAID, BLOCK_BACKOFF
    if "denied" in text or status in (401, 403, 407):
        return Health.BLOCKED, BLOCK_BACKOFF
    if "blocked" in text or status == 451:
        return Health.BLOCKED, BLOCK_BACKOFF
    if "unavailable" in text or status == 0 or status >= 500:
        return Health.UNAVAILABLE, RATE_LIMIT_BACKOFF
    if "not found" in text:
        # A 404 is an answer, not a failure of the provider.
        return Health.OK, 0.0
    return Health.UNAVAILABLE, RATE_LIMIT_BACKOFF


# --------------------------------------------------------------- the plugin API


@dataclass
class Observation:
    """One normalised thing a provider found, with its provenance attached.

    Providers return these rather than writing into a ``ScanResult`` so that a
    provider can be used by a module, by the router, by the search layer or by
    a test harness without any of them having to agree on a result object.
    """

    label: str
    value: Any
    acquisition: Acquisition
    confidence: str = "likely"
    detail: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


class Provider:
    """The interface every external source implements.

    Six methods, and only :meth:`collect` is mandatory. The rest have
    defaults that are correct for a simple source, so adding a provider is one
    small class rather than a form to fill in.

    A provider must never raise out of :meth:`collect`. The router catches
    anything that escapes, but a caught exception costs that rung of the
    ladder, and the fallback below it then runs for the wrong reason.
    """

    info: ProviderInfo

    #: Entity or target kinds this provider can be asked about. Empty means
    #: "the caller decides", which is right for search engines.
    accepts: frozenset[str] = frozenset()

    def __init__(self, fetcher: Any = None, config: Any = None) -> None:
        self.http = fetcher
        self.config = config

    # -- the six ------------------------------------------------------------

    def metadata(self) -> ProviderInfo:
        return self.info

    def health(self, health: ProviderHealth | None = None) -> Health:
        """Whether this provider could answer, before it is asked.

        The default is a pure declaration check - key present? paid and not
        enabled? - so it costs nothing and can be called while building a plan.
        """
        info = self.info
        if info.availability is Availability.DISABLED:
            return Health.DISABLED
        if info.requires_key and not self._has_key(info.requires_key):
            return Health.PAID if info.availability is Availability.PAID \
                else Health.NEEDS_KEY
        if info.availability is Availability.PAID and not self._paid_enabled():
            return Health.PAID
        if health is not None and not health.usable(info.name):
            return health.health(info.name)
        return Health.OK

    def discover(self, target: str, **kw: Any) -> list[str]:
        """Cheap probe for *what this provider could tell us* about a target.

        Default: nothing to announce. Providers that can enumerate (a search
        engine offering suggestions, a registry offering related records)
        override it so the planner can order work without spending a request.
        """
        return []

    def collect(self, target: str, **kw: Any) -> list[Observation]:  # pragma: no cover
        raise NotImplementedError

    def normalize(self, observations: list[Observation]) -> list[Observation]:
        """De-duplicate and tidy. The default keeps the first of each
        ``(label, value)`` pair, which is the behaviour every simple provider
        wants and the one a sloppy provider forgets."""
        seen: set[tuple[str, str]] = set()
        out: list[Observation] = []
        for obs in observations:
            key = (obs.label.strip().lower(), str(obs.value).strip().lower())
            if key in seen:
                continue
            seen.add(key)
            out.append(obs)
        return out

    def score(self, obs: Observation) -> float:
        """How much this provider's word is worth, 0..1.

        A default rather than an abstract, because the honest default is "an
        ordinary public source" and a provider that has no opinion should not
        be forced to invent one.
        """
        return 0.6

    # -- helpers ------------------------------------------------------------

    def _has_key(self, name: str) -> bool:
        cfg = self.config
        return bool(cfg and getattr(cfg, "has", lambda _n: False)(name))

    def _paid_enabled(self) -> bool:
        cfg = self.config
        if cfg is None:
            return False
        return bool(getattr(cfg, "option", lambda *_a: False)("allow_paid", False))


_PROVIDERS: dict[str, type[Provider]] = {}


def register_provider(cls: type[Provider]) -> type[Provider]:
    """Class decorator mirroring ``registry.register`` for modules."""
    name = cls.info.name
    if name in _PROVIDERS:
        raise ValueError(f"duplicate provider name: {name}")
    _PROVIDERS[name] = cls
    return cls


def all_providers() -> list[type[Provider]]:
    return sorted(_PROVIDERS.values(), key=lambda c: c.info.name)


def get_provider(name: str) -> type[Provider] | None:
    return _PROVIDERS.get(name)


# ------------------------------------------------- bridging the existing keys


#: How the keys NOVA already knows about map onto the availability vocabulary.
#: Derived from ``config.KEY_INFO`` rather than duplicated, so the costs stay
#: in the one place a test already asserts against.
def availability_of_key(name: str) -> Availability:
    """What a key-backed source costs, read from its own declaration.

    ``KEY_INFO[name]["availability"]`` is authoritative and every entry
    declares one; a test asserts that. It is declared rather than parsed out of
    the free-text ``cost`` line because that line is written for a human and
    does not survive matching: SecurityTrails' honest cost string is *"paid -
    no free tier advertised"*, and every substring rule that catches "paid"
    also catches the "free" three words later and calls a $500/month source
    free. The fallback below exists only for a key added without the field.
    """
    from .config import key_info

    info = key_info(name)
    if not info.get("modules"):
        # Declared but nothing reads it. Saying FREE would imply capability.
        return Availability.DISABLED

    declared = str(info.get("availability", "")).strip().lower()
    if declared:
        try:
            return Availability(declared)
        except ValueError:
            pass

    cost = str(info.get("cost", "")).lower().strip()
    if cost.startswith("paid"):
        return Availability.PAID
    if not info.get("required"):
        return Availability.OPTIONAL_KEY
    return Availability.USER_KEY if "free" in cost else Availability.PAID


def key_provider_rows(config: Any = None) -> list[tuple[str, Availability, str]]:
    """``[(label, availability, note)]`` for every key-backed source.

    Feeds the Source Availability section and the settings window, so the two
    cannot disagree about whether something costs money.
    """
    from .config import KEY_INFO

    rows: list[tuple[str, Availability, str]] = []
    for name, info in sorted(KEY_INFO.items()):
        avail = availability_of_key(name)
        have = bool(config and getattr(config, "has", lambda _n: False)(name))
        if avail is Availability.DISABLED:
            note = "declared, but no module reads it"
        elif have:
            note = "key present"
        elif avail is Availability.PAID:
            note = "no key - paid source, not queried"
        elif avail is Availability.OPTIONAL_KEY:
            note = "no key - works anyway, at a lower rate limit"
        else:
            note = "no key - not queried"
        rows.append((str(info.get("label", name)), avail, note))
    return rows
