"""Breach exposure.

Two very different questions, so two modules:

``breaches``  which incidents are publicly known to involve this *domain*.
              Free, keyless, and about an organisation rather than a person.

``pwned``     whether this specific *address* appears in HIBP's index. This
              needs a paid HIBP key; without one the module is skipped rather
              than faked, and the console tells you why.

This tool never looks up, downloads or displays breached passwords. Knowing
that an address was in a breach is investigative context; the credentials
themselves are not, and handling them is how OSINT work turns into something
else entirely.
"""

from __future__ import annotations

import urllib.parse

from ..core.http import hostname_of
from ..core.models import Confidence, ScanResult, Severity, TargetType
from ..core.registry import Module, register

HIBP = "https://haveibeenpwned.com/api/v3"


@register
class DomainBreachModule(Module):
    name = "breaches"
    title = "Known breaches for this domain"
    description = "Public HIBP incident list scoped to the organisation's domain."
    accepts = frozenset({TargetType.DOMAIN, TargetType.EMAIL, TargetType.URL})

    def run(self, target: str, result: ScanResult) -> None:
        domain = target.split("@")[-1] if "@" in target else hostname_of(target)
        rows = self.http.get_json(
            f"{HIBP}/breaches?Domain={urllib.parse.quote(domain)}",
            headers={"Accept": "application/json"},
        )
        if not isinstance(rows, list):
            result.error("HIBP breach list unavailable")
            return
        if not rows:
            result.add("known breaches", f"none recorded for {domain}", source="hibp")
            return

        total = sum(int(r.get("PwnCount") or 0) for r in rows)
        result.add("known breaches", f"{len(rows)} incident(s), {total:,} accounts total",
                   source="hibp", severity=Severity.HIGH)
        for r in sorted(rows, key=lambda r: str(r.get("BreachDate", "")), reverse=True):
            classes = ", ".join(r.get("DataClasses", [])[:6])
            result.add(
                f"{r.get('Title')} ({r.get('BreachDate')})",
                f"{int(r.get('PwnCount') or 0):,} accounts - {classes}",
                source="hibp",
                url=f"https://haveibeenpwned.com/PwnedWebsites#{r.get('Name')}",
                severity=Severity.HIGH if r.get("IsVerified") else Severity.NOTABLE,
                confidence=Confidence.CONFIRMED if r.get("IsVerified") else Confidence.POSSIBLE,
                extra={"verified": bool(r.get("IsVerified")),
                       "sensitive": bool(r.get("IsSensitive"))},
            )


@register
class AccountBreachModule(Module):
    name = "pwned"
    title = "Breach exposure for this address"
    description = "HIBP account lookup (requires a paid HIBP API key)."
    accepts = frozenset({TargetType.EMAIL})
    requires_key = "hibp"

    def run(self, target: str, result: ScanResult) -> None:
        resp = self.http.get(
            f"{HIBP}/breachedaccount/{urllib.parse.quote(target)}?truncateResponse=false",
            headers={
                "hibp-api-key": self.config.key("hibp") or "",
                "User-Agent": "nova_osint",
                "Accept": "application/json",
            },
            use_cache=False,
        )
        if resp.status == 404:
            result.add("breach exposure", "not found in any indexed breach", source="hibp")
            return
        if resp.status == 401:
            result.error("HIBP rejected the API key")
            return
        rows = resp.json()
        if not isinstance(rows, list):
            result.error(f"HIBP returned HTTP {resp.status}")
            return

        result.add("breach exposure", f"present in {len(rows)} breach(es)", source="hibp",
                   severity=Severity.HIGH)
        for r in sorted(rows, key=lambda r: str(r.get("BreachDate", "")), reverse=True):
            result.add(
                f"{r.get('Title')} ({r.get('BreachDate')})",
                ", ".join(r.get("DataClasses", [])),
                source="hibp",
                url=f"https://haveibeenpwned.com/PwnedWebsites#{r.get('Name')}",
                severity=Severity.HIGH,
            )

        pastes = self.http.get_json(
            f"{HIBP}/pasteaccount/{urllib.parse.quote(target)}",
            headers={"hibp-api-key": self.config.key("hibp") or "", "User-Agent": "nova_osint"},
            use_cache=False,
        )
        if isinstance(pastes, list) and pastes:
            result.add("pastes", f"{len(pastes)} paste(s) contain this address", source="hibp",
                       severity=Severity.HIGH)


XON = "https://api.xposedornot.com/v1"


@register
class XposedOrNotModule(Module):
    """Breach exposure for an address, free and keyless (XposedOrNot).

    The free answer to the question ``pwned`` needs a paid key for. Reports
    breach names, years and the *kinds* of data exposed - never passwords,
    hashes or password-strength figures, which the API also returns and this
    module deliberately does not read.

    Low-volume by the provider's terms (25/hour per IP), so it runs once per
    address and caches. Being in a breach list is a fact about the *address*:
    it says the address existed by that date, not who owns it.
    """

    name = "xposedornot"
    title = "Breach exposure (free)"
    description = "XposedOrNot breach names, years and exposed data kinds - no key."
    accepts = frozenset({TargetType.EMAIL})

    def refuses(self, target: str) -> str | None:
        from ..core.addresses import judge_address

        if judge_address(target).kind == "automated":
            return "automated mailbox"
        return None

    def run(self, target: str, result: ScanResult) -> None:
        address = target.strip().lower()
        resp = self.http.get(
            f"{XON}/breach-analytics?email={urllib.parse.quote(address)}",
            headers={"Accept": "application/json"}, timeout=25)
        if resp.status == 404:
            result.add("breach exposure", "not in any breach XposedOrNot indexes",
                       source="xposedornot", confidence=Confidence.LIKELY)
            return
        if resp.status == 429:
            result.error("XposedOrNot rate limit reached (25/hour)")
            return
        data = resp.json()
        if not isinstance(data, dict):
            result.error(f"XposedOrNot answered HTTP {resp.status}")
            return
        details = ((data.get("ExposedBreaches") or {}).get("breaches_details")) or []
        if not details:
            result.add("breach exposure", "not in any breach XposedOrNot indexes",
                       source="xposedornot", confidence=Confidence.LIKELY)
            return
        years = sorted({str(d.get("xposed_date", ""))[:4] for d in details
                        if str(d.get("xposed_date", ""))[:4].isdigit()})
        result.add("breach exposure",
                   f"present in {len(details)} breach(es)"
                   + (f", {years[0]}-{years[-1]}" if years else ""),
                   source="xposedornot", severity=Severity.HIGH,
                   confidence=Confidence.CONFIRMED,
                   extra={"earliest": years[0] if years else None,
                          "note": "the address existed by the earliest year; "
                                  "it does not say who uses it"})
        for d in sorted(details, key=lambda d: str(d.get("xposed_date", "")),
                        reverse=True)[:40]:
            kinds = [k.strip() for k in str(d.get("xposed_data", "")).split(";")
                     if k.strip()]
            result.add(
                f"{d.get('breach')} ({d.get('xposed_date')})",
                ", ".join(kinds[:8]),
                source="xposedornot",
                url=f"https://xposedornot.com/xposed#{urllib.parse.quote(str(d.get('breach')))}",
                severity=Severity.HIGH if str(d.get("verified")).lower() == "yes"
                else Severity.NOTABLE,
                confidence=Confidence.CONFIRMED if str(d.get("verified")).lower() == "yes"
                else Confidence.POSSIBLE,
                extra={"domain": d.get("domain"), "industry": d.get("industry"),
                       "verified": str(d.get("verified")).lower() == "yes"},
            )
