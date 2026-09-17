"""Polite, dependency-free HTTP layer.

Everything network-facing in this project goes through :class:`Fetcher`, which
gives us six things in one place:

* **per-host rate limiting** - we are a guest on other people's infrastructure
* **bounded concurrency** - one global worker pool, not one per module
* **an on-disk cache** - re-running a scan should not re-hit crt.sh
* **retry with ``Retry-After``** - the server's own number, not our guess
* **an honest identity** - one configurable User-Agent that says what we are
* **uniform error handling** - modules get a ``Response``, never an exception

Only the standard library is used so the tool runs anywhere Python does.
``requests`` would be nicer but is not worth a hard dependency for a tool people
drop onto a jump box.

What this layer deliberately does **not** do
--------------------------------------------

It does not pretend to be a browser, solve CAPTCHAs, rotate identities, or work
around WAFs, bot detection, authentication or IP blocks. When a source says no,
that answer is recorded - :class:`AccessStatus` gives the refusal a name and it
travels all the way into the report - and the scan moves on. A source that does
not want automated traffic is a source this tool does not read.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import random
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, TypeVar

from .logging_config import get_logger
from .retry import RetryPolicy

log = get_logger("http")

#: We identify ourselves. A tool that fakes a Chrome fingerprint is asking to
#: be treated as a browser by sources that have decided browsers are fine and
#: scrapers are not - which is a decision that belongs to them, not to us.
#: Override with ``--user-agent`` or ``settings.user_agent`` if a source you are
#: authorised to query asks you to identify differently.
VERSION = "1.1.0"
DEFAULT_UA = f"NOVA-OSINT/{VERSION} (+https://github.com/UnoRfl/nova-osint)"

#: Threads in the shared pool carry this prefix, which is how :meth:`Fetcher.map`
#: notices it is being called from inside itself.
_WORKER_PREFIX = "nova-http"

#: Request headers whose presence makes a response unsafe to share via the
#: on-disk cache - it may be personalised, authorised, or simply not ours.
_AUTH_HEADERS = frozenset({
    "authorization", "cookie", "hibp-api-key", "key", "x-api-key",
    "x-auth-token", "api-key", "token",
})

T = TypeVar("T")
R = TypeVar("R")


class AccessStatus(str, Enum):
    """What a source's answer *means*, in one word an investigator can act on.

    This is the vocabulary the report uses when a module comes back empty. "No
    findings" and "the source refused to talk to us" look identical in a list
    of results and are completely different facts.
    """

    OK = "ok"
    NOT_FOUND = "not found"
    RATE_LIMITED = "rate limited"
    ACCESS_DENIED = "access denied"
    BLOCKED = "blocked"
    UNAVAILABLE = "unavailable"
    CLIENT_ERROR = "client error"

    @property
    def is_refusal(self) -> bool:
        """True when the source declined, as opposed to answering."""
        return self in (AccessStatus.RATE_LIMITED, AccessStatus.ACCESS_DENIED,
                        AccessStatus.BLOCKED, AccessStatus.UNAVAILABLE)


def classify(status: int, error: str | None = None) -> AccessStatus:
    """Map an HTTP status (or a transport failure) onto :class:`AccessStatus`."""
    if status == 0:
        return AccessStatus.UNAVAILABLE
    if 200 <= status < 400:
        return AccessStatus.OK
    if status == 404 or status == 410:
        return AccessStatus.NOT_FOUND
    if status == 429:
        return AccessStatus.RATE_LIMITED
    if status in (401, 402, 403, 407):
        return AccessStatus.ACCESS_DENIED
    if status == 451:
        return AccessStatus.BLOCKED
    if status >= 500:
        return AccessStatus.UNAVAILABLE
    return AccessStatus.CLIENT_ERROR


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    error: str | None = None
    elapsed: float = 0.0
    from_cache: bool = False
    #: How many requests it took, including the first. >1 means we retried.
    attempts: int = 1

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 300

    @property
    def access(self) -> AccessStatus:
        return classify(self.status, self.error)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self, default: Any = None) -> Any:
        try:
            return json.loads(self.body)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            return default

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def describe(self) -> str:
        """One line fit for an error list: ``rate limited (HTTP 429)``."""
        if self.error:
            return f"{self.access.value}: {self.error}"
        return f"{self.access.value} (HTTP {self.status})"


class _RateLimiter:
    """One token bucket per host: requests at least ``delay`` seconds apart.

    The delay is drawn from ``[delay_min, delay_max]`` rather than being fixed,
    which keeps parallel workers from locking into lockstep on one host.
    """

    def __init__(self, delay_min: float, delay_max: float | None = None) -> None:
        self.delay_min = max(0.0, delay_min)
        self.delay_max = max(self.delay_min, delay_max if delay_max is not None else delay_min)
        self._next: dict[str, float] = {}
        self._lock = threading.Lock()

    @property
    def delay(self) -> float:  # kept for callers that just want "roughly how long"
        return self.delay_min

    def wait(self, host: str) -> None:
        if self.delay_max <= 0:
            return
        while True:
            with self._lock:
                now = time.monotonic()
                ready = self._next.get(host, 0.0)
                if now >= ready:
                    self._next[host] = now + random.uniform(self.delay_min, self.delay_max)
                    return
                sleep_for = ready - now
            time.sleep(min(sleep_for, 0.25))

    def pause(self, host: str, seconds: float) -> None:
        """Hold every worker off ``host`` for ``seconds`` (used for 429s)."""
        with self._lock:
            self._next[host] = max(self._next.get(host, 0.0), time.monotonic() + seconds)


class _Cache:
    """Content-addressed response cache, keyed on method + url + body."""

    def __init__(self, directory: Path, ttl: float) -> None:
        self.dir = directory
        self.ttl = ttl
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode()).hexdigest()[:32]
        return self.dir / f"{digest}.json"

    def get(self, key: str) -> Response | None:
        p = self._path(key)
        try:
            if time.time() - p.stat().st_mtime > self.ttl:
                return None
            raw = json.loads(p.read_text("utf-8"))
        except (OSError, json.JSONDecodeError, KeyError, ValueError):
            return None
        try:
            return Response(
                url=raw["url"],
                status=raw["status"],
                headers=raw["headers"],
                body=bytes.fromhex(raw["body"]),
                error=raw["error"],
                from_cache=True,
            )
        except (KeyError, TypeError, ValueError):
            return None  # a cache entry from an older layout is just a miss

    def put(self, key: str, resp: Response) -> None:
        if resp.error and resp.status == 0:
            return  # transport failures are usually transient; do not freeze them
        if resp.access in (AccessStatus.RATE_LIMITED, AccessStatus.UNAVAILABLE):
            return  # nor should "come back later" be remembered for an hour
        try:
            self._path(key).write_text(
                json.dumps(
                    {
                        "url": resp.url,
                        "status": resp.status,
                        "headers": resp.headers,
                        "body": resp.body.hex(),
                        "error": resp.error,
                    }
                ),
                "utf-8",
            )
        except OSError:
            pass  # a cache that cannot write is a cache miss, not a failure


def _decompress(raw: bytes, encoding: str) -> bytes:
    try:
        if encoding == "gzip":
            return gzip.decompress(raw)
        if encoding == "deflate":
            return zlib.decompress(raw, -zlib.MAX_WBITS)
    except (OSError, zlib.error, EOFError):
        return raw
    return raw


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Turns a 3xx into a returned response instead of a followed hop.

    Username enumeration needs to see the redirect itself: plenty of sites
    answer an unclaimed handle with 302 -> /login rather than a 404.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class Fetcher:
    def __init__(
        self,
        *,
        timeout: float = 12.0,
        concurrency: int = 24,
        per_host_delay: float = 0.30,
        per_host_delay_max: float | None = None,
        retries: int = 2,
        user_agent: str = DEFAULT_UA,
        cache_dir: Path | None = None,
        cache_ttl: float = 3600.0,
        proxy: str | None = None,
        verify_tls: bool = True,
        retry_policy: RetryPolicy | None = None,
    ) -> None:
        self.timeout = timeout
        self.retries = retries
        self.user_agent = user_agent or DEFAULT_UA
        self.policy = retry_policy or RetryPolicy(max_retries=max(0, retries))
        self.limiter = _RateLimiter(per_host_delay, per_host_delay_max)
        self.pool = ThreadPoolExecutor(
            max_workers=max(1, concurrency), thread_name_prefix=_WORKER_PREFIX
        )
        self.cache = _Cache(cache_dir, cache_ttl) if cache_dir else None

        ctx = ssl.create_default_context()
        if not verify_tls:
            # Some OSINT endpoints sit behind expired or mismatched certs.
            # Opt-in only, never the default.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            log.warning("TLS certificate verification is OFF for this run")

        proxy_handlers: list[urllib.request.BaseHandler] = []
        if proxy:
            proxy_handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
            log.info("routing requests through proxy %s", proxy)

        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx), _NoRedirect(), *proxy_handlers
        )
        self._redirecting = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx), *proxy_handlers
        )

    # ----------------------------------------------------------------- requests

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
        method: str = "GET",
        data: bytes | None = None,
        use_cache: bool = True,
        timeout: float | None = None,
    ) -> Response:
        cacheable = (
            use_cache
            and self.cache is not None
            and method == "GET"
            and not _has_auth(headers)
        )
        key = f"{method}|{url}|{(data or b'').hex()}|{follow_redirects}"
        if cacheable and self.cache is not None:
            hit = self.cache.get(key)
            if hit is not None:
                log.debug("cache hit %s", url)
                return hit

        host = urllib.parse.urlsplit(url).netloc
        resp = Response(url=url, status=0)
        attempt = 0
        while True:
            self.limiter.wait(host)
            resp = self._once(url, headers, follow_redirects, method, data, timeout)
            attempt += 1
            resp.attempts = attempt

            if not self.policy.should_retry(
                attempt=attempt, status=resp.status, error=resp.error
            ):
                break

            retry_after = resp.header("retry-after")
            if self.policy.exceeds_cap(retry_after):
                # The server asked us to wait longer than a scan should block
                # for. Respect the answer by stopping, not by ignoring it.
                log.warning(
                    "%s asked for Retry-After: %s - longer than we will wait; "
                    "recording as rate limited", host, retry_after,
                )
                break

            wait = self.policy.delay(attempt, retry_after)
            log.info(
                "%s -> %s; waiting %.1fs before retry %d/%d",
                host, resp.describe(), wait, attempt, self.policy.max_retries,
            )
            if resp.status == 429:
                # Hold every other worker off this host too, not just this one.
                self.limiter.pause(host, wait)
            time.sleep(wait)

        if resp.access.is_refusal:
            log.debug("%s %s -> %s", method, url, resp.describe())

        if cacheable and self.cache is not None:
            self.cache.put(key, resp)
        return resp

    def head(self, url: str, **kw: Any) -> Response:
        return self.get(url, method="HEAD", **kw)

    def get_json(self, url: str, default: Any = None, **kw: Any) -> Any:
        return self.get(url, **kw).json(default)

    def _once(
        self,
        url: str,
        headers: dict[str, str] | None,
        follow_redirects: bool,
        method: str,
        data: bytes | None,
        timeout: float | None,
    ) -> Response:
        hdrs = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Language": "en",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
        hdrs.update(headers or {})
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        opener = self._redirecting if follow_redirects else self._opener
        started = time.monotonic()
        try:
            with opener.open(req, timeout=timeout or self.timeout) as raw:
                body = raw.read() if method != "HEAD" else b""
                head = {k.lower(): v for k, v in raw.headers.items()}
                return Response(
                    url=raw.geturl(),
                    status=raw.status,
                    headers=head,
                    body=_decompress(body, head.get("content-encoding", "")),
                    elapsed=time.monotonic() - started,
                )
        except urllib.error.HTTPError as e:
            head = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            try:
                body = e.read()
            except (OSError, ValueError):
                body = b""
            return Response(
                url=url,
                status=e.code,
                headers=head,
                body=_decompress(body, head.get("content-encoding", "")),
                elapsed=time.monotonic() - started,
            )
        except (TimeoutError, urllib.error.URLError, ssl.SSLError, ConnectionError) as e:
            reason = getattr(e, "reason", e)
            return Response(
                url=url, status=0, error=str(reason), elapsed=time.monotonic() - started
            )
        except (ValueError, UnicodeError) as e:  # malformed URL, bad IDN, ...
            return Response(url=url, status=0, error=f"{type(e).__name__}: {e}")

    # ------------------------------------------------------------------ fan-out

    def map(self, fn: Callable[[T], R], items: Iterable[T]) -> list[R]:
        """Run ``fn`` over ``items`` on the shared pool, preserving order.

        A worker that raises yields ``None`` rather than poisoning the scan -
        one dead site must not take 480 others down with it.

        If this is called *from* a pool worker it runs the items in the calling
        thread instead of submitting them. Submitting would be a deadlock: the
        caller occupies a worker while waiting for work that needs a free
        worker to run, and with a small ``--concurrency`` there is none.
        """
        work = list(items)

        def guarded(item: T) -> R | None:
            try:
                return fn(item)
            except Exception as exc:  # noqa: BLE001 - boundary around plugin code
                log.debug("fan-out worker raised %s: %s", type(exc).__name__, exc)
                return None

        if threading.current_thread().name.startswith(_WORKER_PREFIX):
            return [guarded(item) for item in work]
        return list(self.pool.map(guarded, work))

    def close(self) -> None:
        self.pool.shutdown(wait=False, cancel_futures=True)

    def __enter__(self) -> Fetcher:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _has_auth(headers: dict[str, str] | None) -> bool:
    """True when a request carries credentials, so its response is not cacheable."""
    if not headers:
        return False
    return any(name.lower() in _AUTH_HEADERS for name in headers)


def hostname_of(value: str) -> str:
    """Best-effort host extraction from a bare domain or a full URL."""
    if "://" not in value:
        value = "https://" + value
    return urllib.parse.urlsplit(value).netloc.split("@")[-1].split(":")[0]
