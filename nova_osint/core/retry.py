"""When to try again, and how long to wait first.

Pulled out of :mod:`nova_osint.core.http` so the policy is one small, pure,
testable object rather than a branch buried in the request loop.

Two principles decide everything here:

* **Only retry what can plausibly succeed next time.** A 404 will still be a
  404 in four seconds; retrying it wastes the target's capacity and ours.
  Transport failures, 429 and the transient 5xx family are worth another go.
* **The server's own answer wins.** If a response carries ``Retry-After``,
  that number is the wait - not our backoff curve. Ignoring it is how a
  well-behaved client turns into an abusive one.
"""

from __future__ import annotations

import email.utils
import random
import time
from dataclasses import dataclass, field

#: Statuses that mean "not now" rather than "no".
TRANSIENT_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})

#: Statuses that are a settled answer. Retrying these is pointless at best and,
#: for 401/403, looks exactly like someone probing an access control.
PERMANENT_STATUSES = frozenset({400, 401, 402, 403, 404, 405, 410, 451})


def parse_retry_after(value: str | None, *, now: float | None = None) -> float | None:
    """Turn a ``Retry-After`` header into seconds, or ``None`` if unusable.

    The header comes in two shapes: ``Retry-After: 120`` and
    ``Retry-After: Wed, 21 Oct 2026 07:28:00 GMT``. Both are handled; anything
    else is treated as absent rather than guessed at.
    """
    if not value:
        return None
    text = value.strip()
    try:
        return max(0.0, float(text))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    reference = time.time() if now is None else now
    return max(0.0, when.timestamp() - reference)


@dataclass(frozen=True)
class RetryPolicy:
    """Configurable retry behaviour.

    ``max_retries`` is *extra* attempts, so ``max_retries=3`` means up to four
    requests in total and the documented curve of 2s, 4s, 8s.
    """

    max_retries: int = 2
    backoff_base: float = 2.0
    #: Never sleep longer than this on our own backoff curve.
    backoff_cap: float = 30.0
    #: Never honour a ``Retry-After`` longer than this; past it we give up and
    #: report "rate limited" instead of blocking the scan for an hour.
    retry_after_cap: float = 60.0
    #: Fraction of the delay added as random jitter, so parallel workers that
    #: were throttled together do not all come back at the same instant.
    jitter: float = 0.25
    retry_statuses: frozenset[int] = field(default=TRANSIENT_STATUSES)
    #: Connection resets, DNS failures and timeouts (``status == 0``).
    retry_transport: bool = True

    def should_retry(self, *, attempt: int, status: int, error: str | None) -> bool:
        """``attempt`` is 1-based: 1 means "the first request just failed"."""
        if attempt > self.max_retries:
            return False
        if status == 0:
            return self.retry_transport and error is not None
        if status in PERMANENT_STATUSES:
            return False
        return status in self.retry_statuses

    def delay(self, attempt: int, retry_after: str | None = None) -> float:
        """Seconds to wait before attempt ``attempt + 1``.

        A server-supplied ``Retry-After`` is used verbatim (clamped), because
        it is the only number that reflects the server's actual state.
        """
        server_wait = parse_retry_after(retry_after)
        if server_wait is not None:
            return min(server_wait, self.retry_after_cap)
        base = min(self.backoff_base**attempt, self.backoff_cap)
        return base + random.uniform(0.0, base * self.jitter)

    def exceeds_cap(self, retry_after: str | None) -> bool:
        """True when the server asked for a longer wait than we will accept."""
        server_wait = parse_retry_after(retry_after)
        return server_wait is not None and server_wait > self.retry_after_cap
