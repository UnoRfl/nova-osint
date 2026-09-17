"""Polite, dependency-free HTTP layer.

Everything network-facing in this project goes through :class:`Fetcher`, which
gives us four things in one place:

* **per-host rate limiting** - we are a guest on other people's infrastructure
* **bounded concurrency** - one global worker pool, not one per module
* **an on-disk cache** - re-running a scan should not re-hit crt.sh
* **uniform error handling** - modules get a ``Response``, never an exception

Only the standard library is used so the tool runs anywhere Python does.
``requests`` would be nicer but is not worth a hard dependency for a tool people
drop onto a jump box.
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
from pathlib import Path
from typing import Any, TypeVar

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

T = TypeVar("T")
R = TypeVar("R")


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    error: str | None = None
    elapsed: float = 0.0
    from_cache: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 300

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self, default: Any = None) -> Any:
        try:
            return json.loads(self.body)
        except Exception:
            return default

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


class _RateLimiter:
    """One token bucket per host: requests at most ``delay`` seconds apart."""

    def __init__(self, per_host_delay: float) -> None:
        self.delay = per_host_delay
        self._next: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, host: str) -> None:
        if self.delay <= 0:
            return
        while True:
            with self._lock:
                now = time.monotonic()
                ready = self._next.get(host, 0.0)
                if now >= ready:
                    # Jitter keeps parallel workers from locking into lockstep.
                    self._next[host] = now + self.delay * random.uniform(0.85, 1.15)
                    return
                sleep_for = ready - now
            time.sleep(min(sleep_for, 0.25))


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
        except Exception:
            return None
        return Response(
            url=raw["url"],
            status=raw["status"],
            headers=raw["headers"],
            body=bytes.fromhex(raw["body"]),
            error=raw["error"],
            from_cache=True,
        )

    def put(self, key: str, resp: Response) -> None:
        if resp.error and resp.status == 0:
            return  # transport failures are usually transient; do not freeze them
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
        except Exception:
            pass  # a cache that cannot write is a cache miss, not a failure


def _decompress(raw: bytes, encoding: str) -> bytes:
    try:
        if encoding == "gzip":
            return gzip.decompress(raw)
        if encoding == "deflate":
            return zlib.decompress(raw, -zlib.MAX_WBITS)
    except Exception:
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
        per_host_delay: float = 0.35,
        retries: int = 2,
        user_agent: str = DEFAULT_UA,
        cache_dir: Path | None = None,
        cache_ttl: float = 3600.0,
        proxy: str | None = None,
        verify_tls: bool = True,
    ) -> None:
        self.timeout = timeout
        self.retries = retries
        self.user_agent = user_agent
        self.limiter = _RateLimiter(per_host_delay)
        self.pool = ThreadPoolExecutor(max_workers=max(1, concurrency))
        self.cache = _Cache(cache_dir, cache_ttl) if cache_dir else None

        ctx = ssl.create_default_context()
        if not verify_tls:
            # Some OSINT endpoints sit behind expired or mismatched certs.
            # Opt-in only, never the default.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        proxy_handlers: list[urllib.request.BaseHandler] = []
        if proxy:
            proxy_handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))

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
        key = f"{method}|{url}|{(data or b'').hex()}|{follow_redirects}"
        if use_cache and self.cache and method == "GET":
            hit = self.cache.get(key)
            if hit is not None:
                return hit

        host = urllib.parse.urlsplit(url).netloc
        resp = Response(url=url, status=0)
        for attempt in range(self.retries + 1):
            self.limiter.wait(host)
            resp = self._once(url, headers, follow_redirects, method, data, timeout)
            # 429 and 503 are the two statuses worth waiting out.
            if resp.status not in (429, 503) or attempt == self.retries:
                break
            time.sleep(min(2**attempt, 6) + random.random())

        if use_cache and self.cache and method == "GET":
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
            "Accept-Language": "en-US,en;q=0.9",
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
            except Exception:
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
        except Exception as e:  # malformed URL, decoding blowups, ...
            return Response(url=url, status=0, error=f"{type(e).__name__}: {e}")

    # ------------------------------------------------------------------ fan-out

    def map(self, fn: Callable[[T], R], items: Iterable[T]) -> list[R]:
        """Run ``fn`` over ``items`` on the shared pool, preserving order.

        A worker that raises yields ``None`` rather than poisoning the scan -
        one dead site must not take 480 others down with it.
        """

        def guarded(item: T) -> R | None:
            try:
                return fn(item)
            except Exception:
                return None

        return list(self.pool.map(guarded, list(items)))

    def close(self) -> None:
        self.pool.shutdown(wait=False, cancel_futures=True)

    def __enter__(self) -> Fetcher:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def hostname_of(value: str) -> str:
    """Best-effort host extraction from a bare domain or a full URL."""
    if "://" not in value:
        value = "https://" + value
    return urllib.parse.urlsplit(value).netloc.split("@")[-1].split(":")[0]
