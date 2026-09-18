"""Asking a site whether we are allowed, and believing the answer.

NOVA's standing rule is that it never works around a refusal. `robots.txt` is
a refusal issued in advance, and honouring it is the cheapest possible way to
keep that promise: the alternative is finding out by being blocked, which
costs the investigation a source *and* leaves a rejected request in somebody's
logs with our honest user-agent on it.

This exists as its own module because three layers need it - the search
engines, the page fetcher behind them, and the browser - and each of them
arriving at its own answer is how a tool ends up polite in one place and not
in another.

The three rules
---------------

**A missing or broken robots.txt means allowed.** That is what the standard
says, and inventing a stricter reading would silently disable most of the
free web. A 404 is permission; only an actual ``Disallow`` is a refusal.

**An unreachable robots.txt does not mean allowed.** If the host would not
answer at all, we are not in a position to claim we checked. Requests are
allowed to proceed - the fetcher will discover the same unreachability - but
:meth:`RobotsCache.status` reports ``unknown`` rather than ``allowed`` so the
distinction survives into the report, like every other coverage gap here.

**One fetch per host per run.** robots.txt is fetched through the ordinary
:class:`~nova_osint.core.http.Fetcher`, so it is rate limited, cached and
recorded like everything else. Checking politeness must not itself be rude.
"""

from __future__ import annotations

import threading
import urllib.parse
import urllib.robotparser
from dataclasses import dataclass
from typing import Any

__all__ = ["Verdict", "RobotsCache", "robots_url"]


@dataclass(frozen=True)
class Verdict:
    """Whether a URL may be fetched, and on what basis."""

    allowed: bool
    #: "allowed" | "disallowed" | "unknown" - the third is not the first.
    status: str
    reason: str = ""
    #: Crawl-delay the host asked for, in seconds, when it named one.
    crawl_delay: float = 0.0

    def __bool__(self) -> bool:
        return self.allowed


def robots_url(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parts.scheme or "https", parts.netloc,
                                    "/robots.txt", "", ""))


class RobotsCache:
    """One parsed robots.txt per host, fetched through NOVA's own fetcher.

    ``urllib.robotparser`` is used for the parsing and nothing else: its
    ``read()`` would open a socket of its own, which would put a second HTTP
    client in a codebase whose whole rate-limiting and cache story depends on
    there being one.
    """

    def __init__(self, fetcher: Any, user_agent: str = "NOVA-OSINT") -> None:
        self.http = fetcher
        self.user_agent = user_agent
        self._parsers: dict[str, urllib.robotparser.RobotFileParser | None] = {}
        self._lock = threading.Lock()

    def check(self, url: str) -> Verdict:
        host = urllib.parse.urlsplit(url).netloc
        if not host:
            return Verdict(True, "unknown", "not an absolute URL")

        parser = self._parser_for(url, host)
        if parser is None:
            # We could not read the rules. Proceeding is reasonable - the
            # fetcher is about to hit the same wall - but we must not claim
            # to have been given permission.
            return Verdict(True, "unknown", "robots.txt unreachable")

        path = urllib.parse.urlsplit(url).path or "/"
        query = urllib.parse.urlsplit(url).query
        probe = path + (f"?{query}" if query else "")
        allowed = parser.can_fetch(self.user_agent, probe)
        delay = parser.crawl_delay(self.user_agent) or 0.0
        if allowed:
            return Verdict(True, "allowed", crawl_delay=float(delay))
        return Verdict(False, "disallowed",
                       f"{host}/robots.txt disallows {probe}",
                       crawl_delay=float(delay))

    def allows(self, url: str) -> bool:
        return self.check(url).allowed

    # ------------------------------------------------------------- internals

    def _parser_for(self, url: str,
                    host: str) -> urllib.robotparser.RobotFileParser | None:
        with self._lock:
            if host in self._parsers:
                return self._parsers[host]

        parser = self._fetch(url)
        with self._lock:
            self._parsers[host] = parser
        return parser

    def _fetch(self, url: str) -> urllib.robotparser.RobotFileParser | None:
        try:
            resp = self.http.get(robots_url(url))
        except Exception:  # noqa: BLE001 - politeness must never end a run
            return None

        status = int(getattr(resp, "status", 0) or 0)
        if status in (401, 403):
            # The standard reading: a protected robots.txt means the whole
            # site is off limits. Honoured rather than argued with.
            parser = urllib.robotparser.RobotFileParser()
            parser.disallow_all = True
            return parser
        if status == 404 or status == 410:
            parser = urllib.robotparser.RobotFileParser()
            parser.allow_all = True
            return parser
        if not getattr(resp, "ok", False):
            return None

        parser = urllib.robotparser.RobotFileParser()
        try:
            parser.parse(resp.text.splitlines())
        except Exception:  # noqa: BLE001 - a malformed file is not a refusal
            parser.allow_all = True
        return parser


class AllowAll(RobotsCache):
    """For tests and for replay, where nothing is fetched at all."""

    def __init__(self) -> None:  # noqa: D107
        super().__init__(fetcher=None)

    def check(self, url: str) -> Verdict:
        return Verdict(True, "allowed", "robots checking disabled")
