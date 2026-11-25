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
import urllib.parse
from pathlib import Path
from typing import Any

from ..core import sitedata
from ..core.config import DEFAULT_CACHE
from ..core.entities import EntityType
from ..core.models import Confidence, ModuleStatus, ScanResult, Severity, TargetType
from ..core.registry import Module, register

SHERLOCK_DATA_URL = (
    "https://raw.githubusercontent.com/sherlock-project/sherlock/"
    "master/sherlock_project/resources/data.json"
)
CORE_SITES = Path(__file__).resolve().parent.parent / "data" / "sites.json"
SITES_CACHE = DEFAULT_CACHE / "sites.json"
SITES_CACHE_TTL = 7 * 24 * 3600
#: Share of answering sites above which a handle is too common to mean anyone.
#: A distinctive handle - a person's real one - typically lands on 1-8% of a
#: catalogue; "sales" landed on ~38%.
GENERIC_SHARE = 0.25


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


def load_catalogue(http: Any = None, refresh: bool = False,
                   max_rank: int = sitedata.DEFAULT_MAX_RANK
                   ) -> tuple[dict[str, dict], str]:
    """Sherlock's list, minus today's false-positive exclusions, sharpened and
    widened by Maigret's ranked sites. See :mod:`nova_osint.core.sitedata`."""
    sherlock, origin = load_sites(http, refresh=refresh)
    try:
        maigret = sitedata.maigret_sites(http, refresh=refresh, max_rank=max_rank)
        excluded = sitedata.sherlock_exclusions(http, refresh=refresh)
    except Exception:  # noqa: BLE001 - a catalogue that fails is a smaller catalogue
        maigret, excluded = {}, set()
    if not maigret and not excluded:
        return sherlock, origin
    merged, n = sitedata.merge(sherlock, maigret, excluded)
    return merged, (f"{origin} + maigret: {len(merged)} sites "
                    f"({n['upgraded']} upgraded to positive checks, "
                    f"{n['maigret']} added, {n['excluded']} dropped as "
                    f"known false positives)")


def _clean(data: dict) -> dict[str, dict]:
    return {
        k: v
        for k, v in data.items()
        if isinstance(v, dict) and not k.startswith("$") and "url" in v and "errorType" in v
    }


def _random_handle() -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "zz" + "".join(random.choice(alphabet) for _ in range(10))


def _control_for(meta: dict) -> str:
    """A handle nobody owns that this particular site will still accept.

    A control the site itself rejects tests nothing: the request never
    reaches the lookup, and the "it did not claim the control" conclusion is
    drawn from the site's input validation rather than from its user
    database. Sites with a minimum length, or one that forbids digits, used
    to reject the generic control and hand back a free CONFIRMED.

    So the control is re-rolled against the site's own ``regexCheck`` a few
    times, in decreasing order of exoticism. If none fit, the caller finds
    out - :meth:`_check` returns ``not-applicable`` and the hit stays
    unverified rather than being promoted.
    """
    regex = meta.get("regexCheck")
    candidates = [_random_handle(),
                  "zz" + "".join(random.choice(string.ascii_lowercase)
                                 for _ in range(10)),
                  "".join(random.choice(string.ascii_lowercase)
                          for _ in range(16))]
    if not regex:
        return candidates[0]
    for candidate in candidates:
        try:
            if re.match(regex, candidate):
                return candidate
        except re.error:
            return candidate
    return candidates[0]


#: Markers of an interstitial - a page served *instead of* the one asked for.
#: Matched against the title and the opening of the document only, and kept
#: to phrases that only ever appear on such pages: "captcha" alone is not one,
#: because ordinary profile pages load reCAPTCHA in their <head>.
_INTERSTITIAL = (
    "just a moment...", "attention required! | cloudflare",
    "cf-browser-verification", "checking your browser before accessing",
    "verify you are human", "verifying you are human", "ddos-guard",
    "px-captcha", "please verify you are a human", "are you a robot",
    "too many requests", "rate limit exceeded", "access denied",
    "request unsuccessful. incapsula",
)


def _echoes(body: str, handle: str) -> bool:
    """Does the page name the handle - plainly, case-folded or URL-encoded?"""
    if not body or not handle:
        return False
    low = body.casefold()
    needle = handle.casefold()
    return needle in low or urllib.parse.quote(needle).casefold() in low


def _refusal(resp: Any, meta: dict) -> str:
    """Why this answer is a refusal rather than a lookup, or "" if it is one.

    Status codes the site itself documents as its "no such user" answer
    (``errorCode``) are answers, whatever they are numerically.
    """
    bad = meta.get("errorCode")
    documented = {bad} if isinstance(bad, int) else set(bad or [])
    status = resp.status
    if status in documented:
        return ""
    if status == 429:
        return "rate limited"
    if status >= 500:
        return f"server error {status}"
    headers = {k.lower(): str(v).lower() for k, v in (resp.headers or {}).items()}
    if headers.get("cf-mitigated") == "challenge":
        return "bot challenge"
    if status in (401, 403, 407, 451):
        return f"refused ({status})"
    head = resp.text[:3000].lower() if resp.body else ""
    if any(marker in head for marker in _INTERSTITIAL):
        return "bot challenge or block page"
    return ""


@register
class UsernameModule(Module):
    name = "username"
    title = "Username enumeration"
    description = "Checks a handle against social, dev, forum and gaming platforms."
    accepts = frozenset({TargetType.USERNAME, TargetType.EMAIL})
    active = False  # third-party public profile pages, not the target's own infra
    slow = True

    def refuses(self, target: str) -> str | None:
        if "@" in target:
            from ..core.addresses import judge_address

            verdict = judge_address(target)
            if verdict.kind != "personal":
                return (f"{verdict.kind} mailbox - its local part is not a "
                        f"person's handle")
        return None

    def run(self, target: str, result: ScanResult) -> None:
        handle = target.split("@")[0] if "@" in target else target
        refresh = bool(self.config.option("refresh_sites", False))
        max_rank = int(self.config.option("maigret_max_rank",
                                          sitedata.DEFAULT_MAX_RANK) or 0)
        sites, origin = load_catalogue(self.http, refresh=refresh,
                                       max_rank=max_rank)
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

        # A handle that "exists" on a large share of the sites that answered
        # is a common word or name, held by a different stranger on each.
        # Measured rather than listed, so it catches "max" and "dragon" as
        # well as "sales". Every hit is demoted to a lead, none pivots.
        answered_n = sum(1 for h in hits if h and h["outcome"] == "answered")
        generic = (answered_n >= 40 and len(found) / answered_n >= GENERIC_SHARE)
        if generic:
            for hit in found:
                hit["confidence"] = Confidence.POSSIBLE
                hit["verified"] = False
                hit["unverified_reason"] = (
                    "common handle - held on most sites, almost certainly "
                    "by different people")
            result.add(
                "generic handle",
                f"'{handle}' exists on {len(found)} of {answered_n} sites that "
                f"answered ({len(found) / answered_n:.0%}). A handle that "
                f"common names nobody in particular; every hit below is a "
                f"lead at best",
                source="analysis", confidence=Confidence.LIKELY,
                severity=Severity.NOTABLE,
            )

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
                extra={"method": hit["method"], "status": hit["status"],
                       "verified": hit.get("verified"),
                       **({"caution": hit["unverified_reason"]}
                          if hit.get("unverified_reason") else {})},
            )

        # Three different things used to be counted as "unreachable": sites we
        # actually asked, sites where the handle is not even a legal username,
        # and sites that refused or timed out. Reporting a legal-name mismatch
        # as a network failure made every scan of a short handle look broken.
        answered = [h for h in hits if h and h["outcome"] == "answered"]
        not_applicable = [h for h in hits if h and h["outcome"] == "not-applicable"]
        refused = [h for h in hits if h and h["outcome"] == "refused"]
        unreachable = len(items) - len(answered) - len(not_applicable)
        if refused:
            reasons: dict[str, int] = {}
            for h in refused:
                reasons[h["refusal"]] = reasons.get(h["refusal"], 0) + 1
            result.add(
                "sites that refused the lookup",
                f"{len(refused)} - a block page or rate limit is not an answer, "
                f"so these say nothing either way",
                source="username",
                extra={"reasons": reasons,
                       "sites": sorted(h["site"] for h in refused)[:60]},
            )

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

        unverified = [h for h in found if h.get("verified") is False]
        if unverified:
            result.add(
                "hits that could not be verified",
                f"{len(unverified)} of {len(found)} - the control probe did not "
                f"answer, so these are unconfirmed leads",
                source="username",
                confidence=Confidence.CONFIRMED,
                extra={"sites": sorted(h["site"] for h in unverified)[:40]},
            )

        # A confirmed handle is the strongest pivot this tool produces - and
        # only a *verified* one is, which is why this reads `verified` rather
        # than merely being in `found`.
        for hit in found[:40]:
            if not hit.get("verified"):
                continue
            if hit["site"].lower() == "github":
                result.entity(EntityType.USERNAME, handle, relation="account-on-github",
                              evidence="handle-verified",
                              detail="profile confirmed, control handle did not match")

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
        if isinstance(err_type, list):  # newer Sherlock entries combine checks
            err_type = err_type[0] if err_type else "status_code"
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

        # A refusal is not an answer. A rate-limit page, a WAF block or a
        # Cloudflare "just a moment" interstitial carries none of the site's
        # "no such user" text, so a ``message`` site read it as a profile and
        # a 403 on a ``status_code`` site read as "no account". Both are
        # wrong in the same way: the site never looked the handle up.
        refusal = _refusal(resp, meta)
        if refusal:
            return {"site": site, "outcome": "refused", "claimed": False,
                    "status": resp.status, "refusal": refusal}

        body = resp.text if resp.body else ""
        # The site's own catalogue of block pages (Maigret's ``errors``).
        for marker, reason in (meta.get("errors") or {}).items():
            if marker and marker in body:
                return {"site": site, "outcome": "refused", "claimed": False,
                        "status": resp.status, "refusal": str(reason)[:80]}

        presence = meta.get("presenseStrs") or []
        positive = None  # None: the site defines no positive marker
        if presence:
            positive = any(p in body for p in presence)

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
            # Maigret's rule: present AND not absent. Absent-only is what a
            # login wall, a consent page or a redesigned 404 also satisfy.
            claimed = (resp.status < 500 and not any(m in body for m in msgs)
                       and positive is not False)
            confidence = Confidence.LIKELY if resp.ok else Confidence.POSSIBLE
        elif err_type == "response_url":
            claimed = 200 <= resp.status < 300 and positive is not False
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
            # Positive evidence: the site's own "this is a profile" marker,
            # or failing that, the handle itself on the page (SpiderFoot's
            # ``musthavename``). A status code alone is neither.
            "positive": bool(positive) or _echoes(body, handle),
            "catalogue": meta.get("source", "sherlock"),
        }

    def _verify(self, hits: list[dict], sites: dict[str, dict]) -> list[dict]:
        """Re-test each hit with a handle nobody owns, and grade on the answer.

        Three outcomes, and the middle one is the whole point of this rewrite:

        * the control **is** claimed - the site says yes to everybody, so the
          hit carries no information and is dropped;
        * the control **could not be tested** - it timed out, was rate limited,
          or the site's own username rules reject the control string - so
          nothing was verified and the hit keeps the confidence it already had;
        * the control is **correctly rejected** - the hit is CONFIRMED.

        The middle case used to be treated as the third. ``if ctrl and
        ctrl["claimed"]`` is False when ``ctrl`` is ``None``, so a control
        probe that failed promoted its hit to CONFIRMED - and under a sweep of
        481 sites with per-host rate limiting, control probes fail in bulk.
        That is how a scan came back with fifty-six "confirmed" accounts on
        sites that had never been verified at all. An unavailable check must
        never raise confidence; that rule holds everywhere else in this tool
        and this was the one place it did not.
        """
        checks = self.http.map(
            lambda h: (h, self._check(h["site"], h["meta"],
                                      _control_for(h["meta"]))), hits
        )
        kept: list[dict] = []
        for pair in checks:
            if not pair:
                continue
            hit, ctrl = pair
            tested = bool(ctrl) and ctrl.get("outcome") == "answered"
            if tested and ctrl["claimed"]:
                continue  # site claims everything - useless signal
            if tested:
                hit["verified"] = True
                if hit.get("positive", True):
                    hit["confidence"] = Confidence.CONFIRMED
                else:
                    # The site tells the two handles apart, but nothing on
                    # the page names this one: a status code and nothing
                    # else. Real, probably - but not shown.
                    hit["confidence"] = Confidence.LIKELY
                    hit["unverified_reason"] = (
                        "the site rejected a made-up handle, but the page "
                        "never shows this one")
            else:
                # Keep it, say so, and do not pretend it was checked.
                hit["verified"] = False
                hit["unverified_reason"] = (
                    "the control probe did not answer"
                    if not ctrl else
                    "this site's username rules reject any control handle")
                if hit["confidence"] is Confidence.CONFIRMED:
                    hit["confidence"] = Confidence.LIKELY
            kept.append(hit)
        return kept
