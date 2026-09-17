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
