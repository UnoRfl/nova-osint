"""Username enumeration across social and developer platforms.

The site database follows the schema used by the Sherlock project (MIT), so the
482-site list it maintains can be pulled in verbatim with ``--refresh-sites``.
A curated core list ships with this package so the module works offline-ish and
on first run without a fetch.

Detection semantics, per site:

``status_code``   claimed when the profile URL answers 2xx
``message``       claimed when a known "no such user" string is *absent*
``response_url``  claimed when the request is not redirected away

Soft-404s are the main source of false positives in this class of tool: a site
that renders a pretty "user not found" page with HTTP 200 looks like a hit.
``--verify`` re-runs each hit against a random handle on the same site and drops
any site that claims both, which kills most of them.
"""

from __future__ import annotations

import json
import random
import re
import string
import time
from pathlib import Path
from typing import Any

from ..core.config import DEFAULT_CACHE
from ..core.models import Confidence, ModuleStatus, ScanResult, Severity, TargetType
from ..core.registry import Module, register

SHERLOCK_DATA_URL = (
    "https://raw.githubusercontent.com/sherlock-project/sherlock/"
    "master/sherlock_project/resources/data.json"
)
CORE_SITES = Path(__file__).resolve().parent.parent / "data" / "sites.json"
SITES_CACHE = DEFAULT_CACHE / "sites.json"
SITES_CACHE_TTL = 7 * 24 * 3600


def load_sites(http: Any = None, refresh: bool = False) -> tuple[dict[str, dict], str]:
    """Return ``(sites, origin)``.

    Prefers a fresh remote list, falls back to the on-disk cache, then to the
    curated list bundled with the package. Never raises.
    """
    if not refresh and SITES_CACHE.exists():
        try:
            if time.time() - SITES_CACHE.stat().st_mtime < SITES_CACHE_TTL:
                cleaned = _clean(json.loads(SITES_CACHE.read_text("utf-8")))
                return cleaned, f"cache ({len(cleaned)} sites)"
        except Exception:
            pass

    if http is not None:
        resp = http.get(SHERLOCK_DATA_URL, use_cache=False, timeout=25)
        data = resp.json() if resp.ok else None
        if isinstance(data, dict) and len(data) > 50:
            try:
                SITES_CACHE.parent.mkdir(parents=True, exist_ok=True)
                SITES_CACHE.write_text(json.dumps(data), "utf-8")
            except Exception:
                pass
            cleaned = _clean(data)
            return cleaned, f"sherlock-project/sherlock ({len(cleaned)} sites)"

    if SITES_CACHE.exists():  # stale beats nothing
        try:
            cleaned = _clean(json.loads(SITES_CACHE.read_text("utf-8")))
            return cleaned, f"stale cache ({len(cleaned)} sites)"
        except Exception:
            pass

    cleaned = _clean(json.loads(CORE_SITES.read_text("utf-8")))
    return cleaned, f"bundled core list ({len(cleaned)} sites)"


def _clean(data: dict) -> dict[str, dict]:
    return {
        k: v
        for k, v in data.items()
        if isinstance(v, dict) and not k.startswith("$") and "url" in v and "errorType" in v
    }


def _random_handle() -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "zz" + "".join(random.choice(alphabet) for _ in range(10))


@register
class UsernameModule(Module):
    name = "username"
    title = "Username enumeration"
    description = "Checks a handle against social, dev, forum and gaming platforms."
    accepts = frozenset({TargetType.USERNAME, TargetType.EMAIL})
    active = False  # third-party public profile pages, not the target's own infra
    slow = True

    def run(self, target: str, result: ScanResult) -> None:
        handle = target.split("@")[0] if "@" in target else target
        refresh = bool(self.config.option("refresh_sites", False))
        sites, origin = load_sites(self.http, refresh=refresh)
        if not sites:
            result.error("no site database available")
            return

        items = list(sites.items())
        if self.config.max_sites:
            items = items[: self.config.max_sites]
        result.add(
            "site database",
            origin,
            source="local",
            severity=Severity.INFO,
        )

        hits = self.http.map(lambda kv: self._check(kv[0], kv[1], handle), items)
        found = [h for h in hits if h and h["claimed"]]
        nsfw_hidden = 0

        if self.config.option("verify_hits", False) and found:
            found = self._verify(found, sites)

        for hit in sorted(found, key=lambda h: h["site"].lower()):
            if hit.get("nsfw") and not self.config.option("include_nsfw", False):
                nsfw_hidden += 1
                continue
            result.add(
                hit["site"],
                hit["url"],
                source="username",
                url=hit["url"],
                confidence=hit["confidence"],
                severity=Severity.NOTABLE,
                extra={"method": hit["method"], "status": hit["status"]},
            )

        # Three different things used to be counted as "unreachable": sites we
        # actually asked, sites where the handle is not even a legal username,
        # and sites that refused or timed out. Reporting a legal-name mismatch
        # as a network failure made every scan of a short handle look broken.
        answered = [h for h in hits if h and h["outcome"] == "answered"]
        not_applicable = [h for h in hits if h and h["outcome"] == "not-applicable"]
        unreachable = len(items) - len(answered) - len(not_applicable)

        result.add(
            "coverage",
            f"{len(found)} hit(s) across {len(answered)} site(s) that answered, "
            f"of {len(items)} in the database",
            source="username",
            extra={
                "answered": len(answered),
                "handle_not_valid_there": len(not_applicable),
                "unreachable": unreachable,
            },
        )
        if nsfw_hidden:
            result.add(
                "adult-site hits withheld",
                f"{nsfw_hidden} (re-run with --include-nsfw to show)",
                source="username",
            )
        if not_applicable:
            result.add(
                "sites that cannot hold this handle",
                f"{len(not_applicable)} (their username rules reject it)",
                source="username",
            )
        if unreachable:
            result.error(f"{unreachable} site(s) unreachable, timed out or refused")
            if unreachable > len(items) / 2:
                result.degrade(
                    ModuleStatus.PARTIAL,
                    f"only {len(answered)} of {len(items)} sites answered",
                )

        # A confirmed handle is the strongest pivot this tool produces.
        for hit in found[:40]:
            if hit["site"].lower() == "github":
                result.pivot(handle, TargetType.USERNAME, "GitHub profile exists")

    # ------------------------------------------------------------------ checks

    def _check(self, site: str, meta: dict, handle: str) -> dict | None:
        regex = meta.get("regexCheck")
        if regex:
            try:
                if not re.match(regex, handle):
                    # The handle is not a legal username here, so the site was
                    # never asked. That is not a failure and must not be counted
                    # as one.
                    return {"site": site, "outcome": "not-applicable", "claimed": False}
            except re.error:
                pass

        # A handful of sites (Discord) carry the handle in a POST body, so the
        # display URL has no placeholder; fall back to the site's home page
        # rather than printing a link that looks like a profile and is not.
        url = meta["url"].replace("{}", handle)
        if "{}" not in meta["url"]:
            url = meta.get("urlMain", meta["url"])
        probe = (meta.get("urlProbe") or meta["url"]).replace("{}", handle)
        method = (meta.get("request_method") or "GET").upper()
        payload = meta.get("request_payload")
        data = None
        headers = dict(meta.get("headers") or {})
        if payload is not None:
            body = json.dumps(payload).replace("{}", handle)
            data = body.encode()
            headers.setdefault("Content-Type", "application/json")
            if method == "GET":
                method = "POST"

        err_type = meta["errorType"]
        resp = self.http.get(
            probe,
            headers=headers,
            method=method,
            data=data,
            follow_redirects=err_type != "response_url",
            timeout=self.config.timeout,
        )
        if resp.status == 0:
            return None

        claimed = False
        confidence = Confidence.LIKELY
        if err_type == "status_code":
            bad = meta.get("errorCode")
            bad_codes = {bad} if isinstance(bad, int) else set(bad or [])
            claimed = 200 <= resp.status < 300 and resp.status not in bad_codes
            confidence = Confidence.LIKELY
        elif err_type == "message":
            msgs = meta.get("errorMsg") or []
            if isinstance(msgs, str):
                msgs = [msgs]
            body = resp.text
            claimed = resp.status < 500 and not any(m in body for m in msgs)
            confidence = Confidence.LIKELY if resp.ok else Confidence.POSSIBLE
        elif err_type == "response_url":
            claimed = 200 <= resp.status < 300
            confidence = Confidence.LIKELY

        return {
            "site": site,
            "url": url,
            "outcome": "answered",
            "claimed": claimed,
            "status": resp.status,
            "access": resp.access.value,
            "method": err_type,
            "confidence": confidence,
            "nsfw": bool(meta.get("isNSFW")),
            "meta": meta,
        }

    def _verify(self, hits: list[dict], sites: dict[str, dict]) -> list[dict]:
        """Drop sites that also 'find' a handle nobody could own."""
        control = _random_handle()
        checks = self.http.map(
            lambda h: (h, self._check(h["site"], h["meta"], control)), hits
        )
        kept: list[dict] = []
        for pair in checks:
            if not pair:
                continue
            hit, ctrl = pair
            if ctrl and ctrl["claimed"]:
                continue  # site claims everything - useless signal
            hit["confidence"] = Confidence.CONFIRMED
            kept.append(hit)
        return kept
