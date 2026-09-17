"""Collection hygiene: how NOVA behaves on the wire, and how that is enforced.

Everything else in this project is about the honesty of the *output*. This is
about the honesty and safety of the *collection*, which is the other half of
being trustworthy to run.

Three mechanisms, each solving a problem that was found rather than imagined:

:class:`SingleFlight`
    Identical concurrent requests share one response. Two modules asking the
    same DNS-over-HTTPS question at the same moment is normal - the domain
    module and the mail-security module both want the MX record - and it was
    observed in a real scan to make one of the two come back ``200`` with an
    empty body. It also halves the traffic to the source and removes a source of
    non-determinism from replay.

:class:`DomainBudget`
    Rate limiting keyed on the *registrable domain*, not the hostname.
    ``api.github.com``, ``raw.githubusercontent.com`` and ``github.com`` are one
    organisation with one rate limit, and treating them as three independent
    hosts is how a scan gets a 403 while believing it was being polite.

:class:`PassiveGuard`
    Turns ``--passive`` from a promise into a check. A module declaring
    ``active = False`` is *prevented* from reaching infrastructure the target
    controls, rather than trusted not to. The flag and the guard are separate on
    purpose: a mislabelled module is a bug that a promise cannot catch and a
    guard can.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

from .entities import registrable
from .http import hostname_of
from .logging_config import get_logger

log = get_logger("opsec")


# ---------------------------------------------------------------------------
# single flight
# ---------------------------------------------------------------------------


class SingleFlight:
    """De-duplicates concurrent identical calls.

    The first caller for a key does the work; everyone else arriving while it is
    in progress waits and receives the same result. Callers arriving *after* it
    completes do the work again - this is a concurrency primitive, not a cache,
    and conflating the two would silently give every request an unbounded
    lifetime.
    """

    class _Call:
        """One in-flight request, and somewhere to put its outcome.

        The result lives on this object, not in a dictionary keyed by URL. A
        follower holds a reference to the exact call it waited on, so the
        registry entry can be dropped the instant the leader finishes without
        racing the followers that have not read it yet. The first version used a
        shared results dict cleared on a timer, and under load a follower could
        arrive after the clear and redo the request - which is precisely the
        duplicate this class exists to prevent.
        """

        __slots__ = ("done", "value", "error")

        def __init__(self) -> None:
            self.done = threading.Event()
            self.value: Any = None
            self.error: BaseException | None = None

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._inflight: dict[str, SingleFlight._Call] = {}
        self.shared = 0

    def do(self, key: str, fn: Callable[[], Any]) -> Any:
        with self._lock:
            call = self._inflight.get(key)
            if call is None:
                call = self._Call()
                self._inflight[key] = call
                leader = True
            else:
                leader = False
                self.shared += 1

        if not leader:
            if not call.done.wait(timeout=120.0):
                # Waited two minutes on a leader that never finished. Do the
                # work rather than return nothing: a follower that silently
                # gives up turns one slow source into several modules
                # reporting empty.
                log.warning("single-flight wait timed out; retrying %s", key[:80])
                return fn()
            if call.error is not None:
                raise call.error
            return call.value

        try:
            call.value = fn()
        except BaseException as exc:
            # Recorded and re-raised to every follower. Leaving them to wake and
            # find nothing would turn one failure into a silent empty result in
            # each of them.
            call.error = exc
            raise
        finally:
            with self._lock:
                self._inflight.pop(key, None)
            call.done.set()
        return call.value


# ---------------------------------------------------------------------------
# per-organisation rate budget
# ---------------------------------------------------------------------------


def budget_key(url_or_host: str) -> str:
    """The thing a rate limit actually applies to.

    GitHub serves ``api.github.com``, ``github.com`` and
    ``raw.githubusercontent.com``; the rate limit is one budget across all
    three. Keying on hostname lets a scan triple its request rate against one
    organisation while each individual limiter believes it is behaving.
    """
    host = hostname_of(url_or_host) or url_or_host
    # githubusercontent.com is a separate registrable domain from github.com but
    # the same operator and the same budget. Same for the handful below; the
    # list is short because guessing at corporate ownership is worse than not.
    same_operator = {
        "githubusercontent.com": "github.com",
        "githubassets.com": "github.com",
        "gitlab-static.net": "gitlab.com",
        "fbcdn.net": "facebook.com",
        "twimg.com": "twitter.com",
        "licdn.com": "linkedin.com",
    }
    reg = registrable(host) or host
    return same_operator.get(reg, reg)


# ---------------------------------------------------------------------------
# passive enforcement
# ---------------------------------------------------------------------------


class PassiveViolation(RuntimeError):
    """A passive module tried to touch the target's own infrastructure."""


class PassiveGuard:
    """Blocks requests to the target's infrastructure from passive modules.

    ``--passive`` already refuses to *run* modules that declare
    ``active = True``. That covers the honest case. This covers the other one:
    a module that forgets to declare itself, or grows a new request that reaches
    the target after it was written. The flag is a declaration; this is the
    enforcement, and a tool that promises not to touch a target should be able
    to prove it rather than assert it.

    The check is on the registrable domain, so ``www.target.com`` and
    ``mail.target.com`` are caught along with the apex, and a third-party
    aggregator that merely *knows about* the target is not.
    """

    def __init__(self, target: str, extra_allowed: frozenset[str] = frozenset()) -> None:
        self.target_domain = registrable(hostname_of(target) or target)
        self.allowed = extra_allowed
        self.blocked: list[str] = []

    def check(self, url: str) -> None:
        if not self.target_domain:
            return
        host = hostname_of(url)
        if not host:
            return
        reg = registrable(host)
        if reg and reg == self.target_domain and reg not in self.allowed:
            self.blocked.append(url)
            raise PassiveViolation(
                f"passive mode: refusing to contact {host}, which belongs to the "
                f"target ({self.target_domain})"
            )

    def wrap(self, fetcher: Any) -> Any:
        return _GuardedFetcher(fetcher, self)


class _GuardedFetcher:
    """A fetcher that refuses requests the guard rejects."""

    def __init__(self, fetcher: Any, guard: PassiveGuard) -> None:
        self._fetcher = fetcher
        self._guard = guard

    def get(self, url: str, **kw: Any) -> Any:
        self._guard.check(url)
        return self._fetcher.get(url, **kw)

    def head(self, url: str, **kw: Any) -> Any:
        self._guard.check(url)
        return self._fetcher.head(url, **kw)

    def get_json(self, url: str, default: Any = None, **kw: Any) -> Any:
        self._guard.check(url)
        return self._fetcher.get_json(url, default, **kw)

    def map(self, fn: Callable[[Any], Any], items: Any) -> list[Any]:
        return self._fetcher.map(fn, items)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._fetcher, name)


# ---------------------------------------------------------------------------
# egress
# ---------------------------------------------------------------------------

#: Where a scan's traffic should come from. ``direct`` is the default and the
#: honest one; the others exist because some work genuinely requires not
#: revealing the analyst's address, and doing that badly is worse than not doing
#: it at all - which is what :func:`leak_check` is for.
EGRESS_PROFILES = {
    "direct": None,
    "proxy": "",              # filled from --proxy / config
    "tor": "socks5h://127.0.0.1:9050",
}


def leak_check(fetcher: Any, proxied: Any) -> dict[str, Any]:
    """Compare the address each route presents, and say whether they differ.

    The check that makes a proxy claim meaningful. A scan configured to go
    through a proxy, silently falling back to the direct route, looks identical
    to a working one from the inside - and the difference is the analyst's home
    address in someone's logs. Returns a report rather than raising, so the
    caller decides whether a leak is fatal.
    """
    out: dict[str, Any] = {"direct": None, "proxied": None, "leaking": None,
                           "error": None}
    try:
        for label, client in (("direct", fetcher), ("proxied", proxied)):
            if client is None:
                continue
            resp = client.get("https://api.ipify.org?format=json", timeout=15)
            data = resp.json() or {}
            out[label] = data.get("ip") if isinstance(data, dict) else None
    except Exception as exc:  # noqa: BLE001 - a failed check must not be silent
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out
    if out["direct"] and out["proxied"]:
        out["leaking"] = out["direct"] == out["proxied"]
    return out
