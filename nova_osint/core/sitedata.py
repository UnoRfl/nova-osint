"""The username site catalogue: Sherlock's list, sharpened by Maigret's.

Two MIT-licensed catalogues, used for what each is best at (attribution in
NOTICE):

* **Sherlock** (``sherlock-project/sherlock``) - ~480 hand-maintained sites,
  plus a *daily* false-positive exclusion list its CI produces by probing
  every site with random handles. A site on that list claimed a handle that
  does not exist within the last day.
* **Maigret** (``soxoj/maigret``) - ~11,000 sites, of which a few hundred are
  well-ranked and the rest are small forums. What it adds is *positive*
  evidence: ``presenseStrs`` that only appear on a real profile, ``errors``
  strings that mark a block page, and engine templates for whole families of
  forum software.

Sherlock's ``message`` check is negative only - "the not-found text is
absent" - and that is exactly what a login wall, a consent page or a
redesigned 404 also satisfies. Maigret's rule is *present AND not absent*.
Where both catalogues know a site and Maigret has presence strings for it,
Maigret's entry replaces Sherlock's. Where only Sherlock knows a site, its
entry is used unchanged and the module's control probe does the rest.

Everything here is converted into the Sherlock-shaped dict the username
module already reads (``url`` with ``{}``, ``errorType``, ``errorMsg``,
``errorCode``), plus three optional keys:

``presenseStrs``  at least one must appear for a ``message``/``response_url``
                  claim to stand (Maigret's spelling, kept so it greps)
``errors``        ``{substring: reason}`` - the page is a refusal, not an answer
``source``        ``"sherlock"`` or ``"maigret"``, reported with each hit
"""

from __future__ import annotations

import json
import time
import urllib.parse
from pathlib import Path
from typing import Any

from .config import DEFAULT_CACHE

MAIGRET_DATA_URL = (
    "https://raw.githubusercontent.com/soxoj/maigret/main/maigret/resources/data.json"
)
SHERLOCK_EXCLUSIONS_URL = (
    "https://raw.githubusercontent.com/sherlock-project/sherlock/"
    "refs/heads/exclusions/false_positive_exclusions.txt"
)
MAIGRET_CACHE = DEFAULT_CACHE / "maigret-sites.json"
EXCLUSIONS_CACHE = DEFAULT_CACHE / "sherlock-exclusions.txt"
MAIGRET_TTL = 7 * 24 * 3600
#: Sherlock regenerates the list daily; a day-old copy is the freshest there is.
EXCLUSIONS_TTL = 24 * 3600

#: Maigret's long tail is ten thousand small forums with rank 0. They are
#: rarely where a subject is, they are where catalogue rot is worst, and each
#: one is a request. Default to the ranked head; ``max_rank=0`` disables it.
DEFAULT_MAX_RANK = 100_000

_NSFW_TAGS = frozenset({"porn", "adult", "nsfw", "erotic", "sex"})


def host_key(meta: dict[str, Any]) -> str:
    """The site's identity for de-duplication: its host, minus ``www.``."""
    for key in ("urlMain", "url"):
        raw = str(meta.get(key) or "").replace("{}", "x")
        host = (urllib.parse.urlsplit(raw).hostname or "").lower()
        if host:
            return host[4:] if host.startswith("www.") else host
    return ""


# --------------------------------------------------------------------- fetch


def _cached_text(http: Any, url: str, path: Path, ttl: float,
                 refresh: bool) -> tuple[str | None, str]:
    """``(text, how)``: fresh cache, else network, else stale cache, else None."""
    if not refresh and path.exists():
        try:
            if time.time() - path.stat().st_mtime < ttl:
                return path.read_text("utf-8"), "cache"
        except OSError:
            pass
    if http is not None:
        resp = http.get(url, use_cache=False, timeout=30)
        if resp.ok and resp.body:
            text = resp.text
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, "utf-8")
            except OSError:
                pass
            return text, "network"
    if path.exists():
        try:
            return path.read_text("utf-8"), "stale cache"
        except OSError:
            pass
    return None, "unavailable"


def sherlock_exclusions(http: Any, refresh: bool = False) -> set[str]:
    """Site names Sherlock's own CI caught claiming a random handle today."""
    text, _how = _cached_text(http, SHERLOCK_EXCLUSIONS_URL, EXCLUSIONS_CACHE,
                              EXCLUSIONS_TTL, refresh)
    if not text or "<html" in text[:200].lower():
        return set()
    return {line.strip() for line in text.splitlines()
            if line.strip() and not line.startswith("#")}


def maigret_sites(http: Any, refresh: bool = False,
                  max_rank: int = DEFAULT_MAX_RANK) -> dict[str, dict]:
    """Maigret's enabled, ranked sites in Sherlock's shape. Never raises."""
    if max_rank <= 0:
        return {}
    text, _how = _cached_text(http, MAIGRET_DATA_URL, MAIGRET_CACHE,
                              MAIGRET_TTL, refresh)
    if not text:
        return {}
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    return convert_maigret(data, max_rank=max_rank)


# ------------------------------------------------------------------ convert


def _fill(template: str, main: str, subpath: str) -> str:
    return (template.replace("{urlMain}", main.rstrip("/"))
            .replace("{urlSubpath}", subpath or "")
            .replace("{username}", "{}"))


def convert_maigret(data: dict[str, Any],
                    max_rank: int = DEFAULT_MAX_RANK) -> dict[str, dict]:
    """Maigret's ``{"sites", "engines"}`` document -> Sherlock-shaped entries.

    Skipped, deliberately:

    * ``disabled`` - Maigret's maintainers turned it off because it lies;
    * ``activation`` - needs a token fetched first, which plain HTTP cannot do
      honestly;
    * rank 0 or above ``max_rank`` - the unranked long tail.
    """
    sites = data.get("sites") if isinstance(data.get("sites"), dict) else {}
    engines = data.get("engines") if isinstance(data.get("engines"), dict) else {}
    out: dict[str, dict] = {}
    for name, raw in sites.items():
        if not isinstance(raw, dict) or raw.get("disabled") or raw.get("activation"):
            continue
        rank = raw.get("alexaRank") or 0
        if not isinstance(rank, int) or rank <= 0 or rank > max_rank:
            continue
        entry: dict[str, Any] = {}
        engine = engines.get(raw.get("engine") or "")
        if isinstance(engine, dict) and isinstance(engine.get("site"), dict):
            entry.update(engine["site"])
        entry.update(raw)

        main = str(entry.get("urlMain") or "")
        sub = str(entry.get("urlSubpath") or "")
        url = _fill(str(entry.get("url") or ""), main, sub)
        if "{}" not in url:
            continue
        check = entry.get("checkType") or "status_code"
        if check not in ("status_code", "message", "response_url"):
            continue

        conv: dict[str, Any] = {
            "url": url,
            "urlMain": main or url.split("{}")[0],
            "errorType": check,
            "source": "maigret",
            "rank": rank,
        }
        if probe := entry.get("urlProbe"):
            conv["urlProbe"] = _fill(str(probe), main, sub)
        absence = [s for s in entry.get("absenceStrs") or [] if isinstance(s, str) and s]
        presence = [s for s in entry.get("presenseStrs") or [] if isinstance(s, str) and s]
        if absence:
            conv["errorMsg"] = absence
        if presence:
            conv["presenseStrs"] = presence
        if isinstance(entry.get("errors"), dict):
            conv["errors"] = {str(k): str(v) for k, v in entry["errors"].items() if k}
        if entry.get("ignore403"):
            # Maigret's flag means "a 403 here is this site's not-found page".
            conv["errorCode"] = [403]
        if regex := entry.get("regexCheck"):
            conv["regexCheck"] = regex
        if isinstance(entry.get("headers"), dict):
            conv["headers"] = {str(k): str(v) for k, v in entry["headers"].items()}
        if entry.get("requestHeadOnly"):
            conv["request_method"] = "HEAD"
        elif entry.get("requestMethod"):
            conv["request_method"] = str(entry["requestMethod"]).upper()
        if entry.get("requestPayload") is not None:
            conv["request_payload"] = entry["requestPayload"]
        if _NSFW_TAGS & {str(t).lower() for t in entry.get("tags") or []}:
            conv["isNSFW"] = True
        out[name] = conv
    return out


def merge(sherlock: dict[str, dict], maigret: dict[str, dict],
          excluded: set[str] | None = None) -> tuple[dict[str, dict], dict[str, int]]:
    """One catalogue, one entry per host. Returns ``(sites, counts)``.

    Precedence per host: Maigret's entry when it carries presence strings
    (positive evidence beats negative); otherwise Sherlock's, unless
    Sherlock's own CI excluded it today, in which case Maigret's entry (if
    any) stands in and the site is dropped if there is none.
    """
    excluded = excluded or set()
    by_host_m: dict[str, tuple[str, dict]] = {}
    for name, meta in maigret.items():
        key = host_key(meta)
        if key and key not in by_host_m:
            by_host_m[key] = (name, meta)

    sites: dict[str, dict] = {}
    seen: set[str] = set()
    counts = {"sherlock": 0, "maigret": 0, "upgraded": 0, "excluded": 0}
    for name, meta in sherlock.items():
        key = host_key(meta)
        better = by_host_m.get(key)
        if better and better[1].get("presenseStrs"):
            sites[name] = better[1]
            counts["upgraded"] += 1
        elif name in excluded:
            if better:
                sites[name] = better[1]
                counts["upgraded"] += 1
            else:
                counts["excluded"] += 1
                seen.add(key)
                continue
        else:
            sites[name] = {**meta, "source": meta.get("source", "sherlock")}
            counts["sherlock"] += 1
        seen.add(key)

    for key, (name, meta) in by_host_m.items():
        if key in seen:
            continue
        sites[name if name not in sites else f"{name} (maigret)"] = meta
        counts["maigret"] += 1
        seen.add(key)
    return sites, counts
