"""How a fact was obtained, recorded alongside the fact itself.

Every other layer in this project answers *what* was found and *who* said it.
This one answers **how it was fetched**, which is a different question and one
that changes how much a reader should trust the answer.

A name lifted from a search-engine snippet and the same name returned by a
registry API are not the same observation. The first is a third party's
summary of a page that may no longer say that; the second is authoritative.
Before this module the two arrived in the report looking identical, because
``Finding`` recorded the *module* that produced a value and nothing about the
road it travelled.

The three rules
---------------

**A method is never inferred at render time.** It is stamped at the moment of
acquisition by the thing that did the acquiring, because that is the only
place where the truth is known. A renderer that guesses "this looks like an
API result" will eventually guess wrong about the one finding that mattered.

**Never claim a richer method than was used.** :data:`Method` is ordered from
cheapest and most authoritative to most circumstantial, and the router records
the rung that actually answered - not the rung it wanted. A browser result
labelled as an API result is a lie the reader cannot detect.

**A method is not a confidence.** ``Confidence`` says how strongly the source
asserts the value; ``Method`` says how the value reached us. They are
independent: an authoritative registry reached through a browser is still
authoritative, and a guess served by a JSON API is still a guess.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

__all__ = ["Method", "SourceType", "Acquisition", "now"]


def now() -> float:
    """Wall-clock seconds. One function so tests can monkeypatch one thing."""
    return time.time()


class Method(str, Enum):
    """How a value physically arrived, cheapest and most direct first.

    The order is the router's priority ladder, and it is deliberate: anything
    computable locally costs nothing and cannot be rate limited; a documented
    API is both cheaper and more reliable than the page it summarises; a
    search engine is a third party's index of that page; and a browser is the
    most expensive, most fragile and least deniable way to read the same
    thing. NOVA walks down this list and stops at the first rung that answers.
    """

    #: Computed on this machine from data we already hold. No network at all.
    LOCAL = "local"
    #: Served from NOVA's own on-disk HTTP cache.
    CACHE = "cache"
    #: Read back from a previous case in the store.
    STORE = "store"
    #: Re-derived from recorded evidence with the network disabled.
    REPLAY = "replay"
    #: A documented machine endpoint returning structured data.
    API = "api"
    #: A public web page fetched over plain HTTP and parsed.
    PAGE = "page"
    #: A search engine's results, however they were obtained.
    SEARCH = "search"
    #: Driven through a real browser on the operator's machine.
    BROWSER = "browser"
    #: The operator supplied it by hand.
    OPERATOR = "operator"

    @property
    def label(self) -> str:
        return _METHOD_LABELS[self]

    @property
    def is_network(self) -> bool:
        """False for anything that did not leave this machine."""
        return self in (Method.API, Method.PAGE, Method.SEARCH, Method.BROWSER)


_METHOD_LABELS = {
    Method.LOCAL: "computed locally",
    Method.CACHE: "from cache",
    Method.STORE: "from a stored case",
    Method.REPLAY: "replayed from evidence",
    Method.API: "public API",
    Method.PAGE: "public web page",
    Method.SEARCH: "search engine",
    Method.BROWSER: "browser",
    Method.OPERATOR: "supplied by the operator",
}

#: The order the router prefers. Index in this tuple is the rung number.
LADDER: tuple[Method, ...] = (
    Method.LOCAL,
    Method.CACHE,
    Method.STORE,
    Method.API,
    Method.PAGE,
    Method.SEARCH,
    Method.BROWSER,
)


class SourceType(str, Enum):
    """What kind of thing answered, for grouping in the source index."""

    REGISTRY = "registry"          # RDAP, DNS, CT logs - authoritative records
    CODE_HOST = "code host"
    SOCIAL = "social"
    SEARCH_ENGINE = "search engine"
    ARCHIVE = "archive"
    SCHOLARLY = "scholarly"
    DATASET = "dataset"
    SECURITY = "security"
    WEBSITE = "website"
    DOCUMENT = "document"
    IMAGE = "image"
    LOCAL_SYSTEM = "local system"
    UNKNOWN = "unknown"


@dataclass
class Acquisition:
    """The provenance of one observation.

    Deliberately a plain record with no behaviour beyond serialisation, for
    the same reason ``Finding`` is: it gets stored, hashed, replayed and
    rendered, and anything with behaviour eventually acquires a behaviour that
    differs between those four paths.
    """

    method: Method
    #: The adapter, engine or module that did the fetching.
    provider: str
    url: str | None = None
    #: The query that produced it, when the provider is query-driven.
    query: str | None = None
    #: HTTP status, when there was one. 0 means "no HTTP involved".
    status: int = 0
    obtained_at: float = field(default_factory=now)
    #: sha256 of the stored response body, when the evidence store was open.
    evidence: str | None = None
    source_type: SourceType = SourceType.UNKNOWN
    #: True when the answer came out of NOVA's HTTP cache rather than the wire.
    cached: bool = False
    #: Anything the provider wants on the record, e.g. a redirect chain.
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method.value,
            "provider": self.provider,
            "url": self.url,
            "query": self.query,
            "status": self.status or None,
            "obtained_at": self.obtained_at,
            "evidence": self.evidence,
            "source_type": self.source_type.value,
            "cached": self.cached,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Acquisition:
        """Rebuild one from storage, tolerating a record written by an older
        version that did not have every field."""
        return cls(
            method=_coerce(Method, data.get("method"), Method.API),
            provider=str(data.get("provider") or "unknown"),
            url=data.get("url"),
            query=data.get("query"),
            status=int(data.get("status") or 0),
            obtained_at=float(data.get("obtained_at") or 0.0),
            evidence=data.get("evidence"),
            source_type=_coerce(SourceType, data.get("source_type"),
                                SourceType.UNKNOWN),
            cached=bool(data.get("cached")),
            detail=str(data.get("detail") or ""),
        )

    def describe(self) -> str:
        """One line for a report: ``search engine (mojeek)`` or ``public API``."""
        base = self.method.label
        if self.provider and self.provider != self.method.value:
            base = f"{base} ({self.provider})"
        if self.cached:
            base += ", cached"
        return base

    @classmethod
    def from_response(cls, resp: Any, provider: str, *,
                      method: Method = Method.API,
                      query: str | None = None,
                      source_type: SourceType = SourceType.UNKNOWN,
                      evidence: str | None = None,
                      requested: str | None = None) -> Acquisition:
        """Build one from a :class:`~nova_osint.core.http.Response`.

        ``requested`` is the URL that was *asked for*; it matters because a
        redirect makes ``resp.url`` a different address, and the replay layer
        keys recordings on what was requested. Getting that backwards made a
        complete case replay at 0% coverage once already.
        """
        url = requested or getattr(resp, "url", None)
        detail = ""
        landed = getattr(resp, "url", None)
        if landed and url and landed != url:
            detail = f"redirected to {landed}"
        return cls(
            method=method,
            provider=provider,
            url=url,
            query=query,
            status=int(getattr(resp, "status", 0) or 0),
            evidence=evidence,
            source_type=source_type,
            cached=bool(getattr(resp, "from_cache", False)),
            detail=detail,
        )


def _coerce(enum_cls: Any, value: Any, default: Any) -> Any:
    try:
        return enum_cls(value)
    except (ValueError, TypeError):
        return default
