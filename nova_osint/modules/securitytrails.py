"""SecurityTrails: historical DNS and pre-privacy WHOIS.

The one thing no free source gives you is **the past**. crt.sh knows which
certificates exist now, RDAP knows who the registrar is now, and both are
useless when the question is "who registered this before they turned on
privacy protection, and where did it point in 2017?".

SecurityTrails keeps that history, and historical WHOIS in particular is the
single highest-value paid lookup in OSINT work: domains registered before
GDPR-era redaction routinely still have the original registrant name, address
and email sitting in the archive.

Quota - read this before enabling it
------------------------------------

The free tier is around **50 queries per month**. Not per day. That is the
whole reason this module has a depth setting instead of just querying
everything:

``basic`` (default)  1 query   current DNS, subdomain count, apex, rank
``full``             3 queries adds the subdomain list and historical WHOIS

Set it in ``config.json``::

    "module_options": { "securitytrails_depth": "full" }

At ``full`` a free key is exhausted after roughly sixteen scans, so NOVA
defaults to ``basic`` and makes you opt in rather than quietly spending your
month on a scan you did not think about.
"""

from __future__ import annotations

from ..core.http import hostname_of
from ..core.models import Confidence, ModuleStatus, ScanResult, Severity, TargetType
from ..core.registry import Module, register

API = "https://api.securitytrails.com/v1"

#: Record types the /domain endpoint returns under current_dns.
DNS_KEYS = ("a", "aaaa", "mx", "ns", "soa", "txt")


@register
class SecurityTrailsModule(Module):
    name = "securitytrails"
    title = "SecurityTrails history"
    description = "Current DNS with owner names, subdomain count, and (opt-in) historical WHOIS."
    accepts = frozenset({TargetType.DOMAIN, TargetType.URL})
    requires_key = "securitytrails"
    active = False
    slow = True

    def run(self, target: str, result: ScanResult) -> None:
        host = hostname_of(target)
        depth = str(self.config.option("securitytrails_depth", "basic")).lower()

        data = self._get(f"{API}/domain/{host}", result)
        if data is None:
            return

        result.add("queries spent", "1" if depth != "full" else "3", source="securitytrails",
                   extra={"note": "the free tier allows about 50 per month",
                          "depth": depth})

        if apex := data.get("apex_domain"):
            result.add("apex domain", apex, source="securitytrails")
        if (count := data.get("subdomain_count")) is not None:
            result.add("subdomains known", count, source="securitytrails",
                       severity=Severity.NOTABLE if int(count or 0) > 50 else Severity.INFO)
        if rank := data.get("alexa_rank"):
            result.add("traffic rank", f"#{int(rank):,}", source="securitytrails",
                       confidence=Confidence.LIKELY)

        self._current_dns(data, result)

        if depth == "full":
            self._subdomains(host, result)
            self._whois_history(host, result)
        else:
            result.add(
                "history not queried",
                'set "module_options": {"securitytrails_depth": "full"} in config.json '
                "for the subdomain list and historical WHOIS (costs 2 more queries)",
                source="securitytrails",
            )

    # ------------------------------------------------------------------ helpers

    def _get(self, url: str, result: ScanResult) -> dict | None:
        """One request, with SecurityTrails' own failure modes named."""
        resp = self.http.get(
            url,
            headers={"APIKEY": self.config.key("securitytrails") or "",
                     "Accept": "application/json"},
        )
        if resp.status in (401, 403):
            result.degrade(ModuleStatus.BLOCKED, "SecurityTrails rejected the API key")
            result.error("SecurityTrails rejected the API key (check SECURITYTRAILS_API_KEY)")
            return None
        if resp.status == 429:
            result.degrade(ModuleStatus.RATE_LIMITED, "SecurityTrails monthly quota exhausted")
            result.error("SecurityTrails quota exhausted - the free tier is ~50 queries/month")
            return None
        if resp.status == 404:
            result.add("SecurityTrails record", "no entry", source="securitytrails")
            return None
        data = resp.json()
        if not isinstance(data, dict):
            result.error(f"SecurityTrails: {resp.describe()}")
            return None
        return data

    def _current_dns(self, data: dict, result: ScanResult) -> None:
        """Their DNS view carries the *owning organisation*, which plain DNS does not."""
        current = data.get("current_dns")
        if not isinstance(current, dict):
            return
        for key in DNS_KEYS:
            block = current.get(key)
            if not isinstance(block, dict):
                continue
            values = block.get("values")
            if not isinstance(values, list) or not values:
                continue

            rendered = []
            for item in values:
                if not isinstance(item, dict):
                    rendered.append(str(item))
                    continue
                # Each record type names its value differently.
                value = (item.get("ip") or item.get("ipv6") or item.get("host")
                         or item.get("nameserver") or item.get("value") or "")
                org = item.get("ip_organization") or item.get("organization")
                rendered.append(f"{value} ({org})" if org else str(value))
                if key == "a" and item.get("ip"):
                    result.pivot(str(item["ip"]), TargetType.IP, "SecurityTrails current DNS")

            result.add(f"{key.upper()} (with owner)", rendered, source="securitytrails")
            if first_seen := block.get("first_seen"):
                result.add(f"{key.upper()} first seen", first_seen, source="securitytrails",
                           confidence=Confidence.LIKELY)

    def _subdomains(self, host: str, result: ScanResult) -> None:
        data = self._get(f"{API}/domain/{host}/subdomains", result)
        if data is None:
            return
        subs = data.get("subdomains")
        if not isinstance(subs, list) or not subs:
            return
        full = sorted(f"{s}.{host}" for s in subs if isinstance(s, str))
        result.add("subdomains (historical)", full[:200], source="securitytrails",
                   severity=Severity.NOTABLE, confidence=Confidence.LIKELY,
                   extra={"count": len(full),
                          "note": "SecurityTrails has seen these; they may no longer resolve"})
        for name in full[:20]:
            result.pivot(name, TargetType.DOMAIN, "SecurityTrails subdomain history")

    def _whois_history(self, host: str, result: ScanResult) -> None:
        """Registrant details from before the privacy shutter came down."""
        data = self._get(f"{API}/history/{host}/whois", result)
        if data is None:
            return
        items = ((data.get("result") or {}).get("items")
                 if isinstance(data.get("result"), dict) else None)
        if not isinstance(items, list) or not items:
            return

        result.add("WHOIS history", f"{len(items)} archived record(s)",
                   source="securitytrails", severity=Severity.NOTABLE)

        # Walk every archived record and collect the identities that ever
        # appeared. One of them is usually the real owner.
        names: list[str] = []
        emails: list[str] = []
        orgs: list[str] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            for contact in item.get("contact") or []:
                if not isinstance(contact, dict):
                    continue
                for field, bucket in (("name", names), ("email", emails),
                                      ("organization", orgs)):
                    value = str(contact.get(field) or "").strip()
                    if value and value.lower() not in {v.lower() for v in bucket}:
                        bucket.append(value)

        for label, bucket, severity in (
            ("historic registrant name", names, Severity.HIGH),
            ("historic registrant email", emails, Severity.HIGH),
            ("historic registrant org", orgs, Severity.NOTABLE),
        ):
            if bucket:
                result.add(label, bucket[:12], source="securitytrails", severity=severity,
                           confidence=Confidence.LIKELY,
                           extra={"note": "archived registration data; "
                                          "privacy services and resellers appear here too"})

        for address in emails[:8]:
            if "@" in address:
                result.pivot(address, TargetType.EMAIL, "historic WHOIS registrant")

        oldest = items[-1] if items else {}
        if isinstance(oldest, dict) and oldest.get("createdDate"):
            result.add("earliest archived registration", str(oldest["createdDate"])[:10],
                       source="securitytrails")
