"""VirusTotal reputation and passive DNS.

VirusTotal aggregates 70-odd URL and domain blocklists plus its own telemetry,
which makes it the fastest way to answer two questions NOVA could not answer
before: *has anyone flagged this?* and *what else has lived on this IP?*

What it adds over the keyless sources
-------------------------------------

``ip``/``whois``/``dns`` tell you what a target **is**. VirusTotal tells you
what it has been **seen doing**: blocklist verdicts from named vendors, the
categories content filters file it under, its popularity rank, and passive DNS
(every domain VT has observed on an IP, and every IP observed for a domain).
That last one is the real prize - it finds the rest of an operator's estate.

Cost and courtesy
-----------------

The free "public" key allows roughly **4 requests a minute and 500 a day**, and
VirusTotal is explicit that it is for non-commercial use. This module spends
**2 requests per scan** (the object, then its resolutions). If you hit the
minute limit the response is a 429 and NOVA records "rate limited" rather than
hammering it - which is also why ``request_delay_min`` matters if you scan in a
loop.

Reading the verdicts honestly
-----------------------------

A "malicious" count is *how many vendors say so*, not a fact. One vendor out of
seventy is noise and is reported as such; blocklists disagree constantly and
false positives on small domains are routine. NOVA names the vendors so you can
judge the source rather than the number.
"""

from __future__ import annotations

import time

from ..core.entities import EntityType
from ..core.http import hostname_of
from ..core.infra import SAMPLE, SharedVerdict, judge_host
from ..core.models import Confidence, ModuleStatus, ScanResult, Severity, TargetType
from ..core.registry import Module, register

API = "https://www.virustotal.com/api/v3"

#: VT's own docs call these "the stats"; only the first three are verdicts.
VERDICT_KEYS = ("malicious", "suspicious", "harmless", "undetected", "timeout")


def _stamp(value: object) -> str:
    """VT hands out unix timestamps; a date is what a human needs."""
    try:
        return time.strftime("%Y-%m-%d", time.gmtime(int(value)))  # type: ignore[arg-type]
    except (TypeError, ValueError, OSError):
        return str(value)


@register
class VirusTotalModule(Module):
    name = "virustotal"
    title = "VirusTotal reputation"
    description = "Blocklist verdicts, categories, popularity and passive DNS."
    accepts = frozenset({TargetType.DOMAIN, TargetType.URL, TargetType.IP})
    requires_key = "virustotal"
    #: Third-party telemetry only - VT is queried, never the target.
    active = False

    def run(self, target: str, result: ScanResult) -> None:
        # Signals the shared-infrastructure judgement reads, collected as the
        # report is parsed. Reset per run: a Module instance is short-lived,
        # but an attribute surviving between two of them would be a
        # cross-target leak of exactly the kind this module must not make.
        self._as_owner = ""
        self._ptr = ""
        self._cert_cn = ""
        is_ip = result.target_type is TargetType.IP
        subject = target if is_ip else hostname_of(target)
        kind = "ip_addresses" if is_ip else "domains"

        resp = self.http.get(
            f"{API}/{kind}/{subject}",
            headers={"x-apikey": self.config.key("virustotal") or "",
                     "Accept": "application/json"},
        )
        if resp.status == 401:
            result.degrade(ModuleStatus.BLOCKED, "VirusTotal rejected the API key")
            result.error("VirusTotal rejected the API key (check VT_API_KEY)")
            return
        if resp.status == 429:
            result.degrade(
                ModuleStatus.RATE_LIMITED,
                "VirusTotal quota reached (the free key allows ~4/min, 500/day)",
            )
            result.error("VirusTotal quota reached - try again in a minute")
            return
        if resp.status == 404:
            result.add("VirusTotal record", f"no entry for {subject}", source="virustotal")
            return

        data = resp.json()
        attrs = (data or {}).get("data", {}).get("attributes") if isinstance(data, dict) else None
        if not isinstance(attrs, dict):
            result.error(f"VirusTotal: {resp.describe()}")
            return

        self._verdicts(attrs, subject, result)
        self._context(attrs, is_ip, result)
        self._resolutions(kind, subject, is_ip, result)

    # ------------------------------------------------------------------ pieces

    def _verdicts(self, attrs: dict, subject: str, result: ScanResult) -> None:
        stats = attrs.get("last_analysis_stats")
        if not isinstance(stats, dict):
            return
        counts = {k: int(stats.get(k) or 0) for k in VERDICT_KEYS}
        flagged = counts["malicious"] + counts["suspicious"]
        engines = counts["malicious"] + counts["suspicious"] + counts["harmless"] \
            + counts["undetected"]

        result.add(
            "blocklist verdict",
            f"{counts['malicious']} malicious, {counts['suspicious']} suspicious "
            f"of {engines} engines",
            source="virustotal",
            url=f"https://www.virustotal.com/gui/search/{subject}",
            severity=Severity.HIGH if counts["malicious"]
            else Severity.NOTABLE if counts["suspicious"] else Severity.INFO,
            # The counts are a fact; what they mean is not.
            confidence=Confidence.CONFIRMED,
            extra={**counts, "note": "vendor opinions, not ground truth - "
                                     "one or two hits on a small domain is usually noise"},
        )

        # Name the vendors. "3 engines flagged it" is unactionable; "Fortinet
        # and Sophos call it phishing" can be checked.
        if flagged:
            results = attrs.get("last_analysis_results")
            if isinstance(results, dict):
                named = sorted(
                    f"{vendor}: {(verdict or {}).get('result') or (verdict or {}).get('category')}"
                    for vendor, verdict in results.items()
                    if isinstance(verdict, dict)
                    and verdict.get("category") in ("malicious", "suspicious")
                )
                if named:
                    result.add("flagged by", named[:20], source="virustotal",
                               severity=Severity.HIGH if counts["malicious"] else Severity.NOTABLE)

        votes = attrs.get("total_votes")
        if isinstance(votes, dict) and (votes.get("malicious") or votes.get("harmless")):
            result.add(
                "community votes",
                f"{votes.get('harmless', 0)} harmless, {votes.get('malicious', 0)} malicious",
                source="virustotal",
                confidence=Confidence.POSSIBLE,
                extra={"note": "unverified public votes; trivially gamed"},
            )
        if (reputation := attrs.get("reputation")) not in (None, 0):
            result.add("reputation score", reputation, source="virustotal",
                       severity=Severity.NOTABLE if isinstance(reputation, int)
                       and reputation < 0 else Severity.INFO,
                       confidence=Confidence.LIKELY)

    def _context(self, attrs: dict, is_ip: bool, result: ScanResult) -> None:
        categories = attrs.get("categories")
        if isinstance(categories, dict) and categories:
            unique = sorted({str(v) for v in categories.values() if v})
            result.add("content categories", unique, source="virustotal",
                       confidence=Confidence.LIKELY,
                       extra={"by_vendor": categories})

        ranks = attrs.get("popularity_ranks")
        if isinstance(ranks, dict) and ranks:
            best = sorted(
                (int(v.get("rank", 0)), k) for k, v in ranks.items()
                if isinstance(v, dict) and v.get("rank")
            )
            if best:
                rank, provider = best[0]
                result.add("popularity rank", f"#{rank:,} ({provider})",
                           source="virustotal", confidence=Confidence.LIKELY,
                           extra={"all": {k: v.get("rank") for k, v in ranks.items()
                                          if isinstance(v, dict)}})

        if tags := attrs.get("tags"):
            result.add("VirusTotal tags", sorted(str(t) for t in tags), source="virustotal",
                       severity=Severity.NOTABLE)

        if is_ip:
            for key, label in (("as_owner", "AS owner"), ("asn", "ASN"),
                               ("network", "network"), ("country", "country"),
                               ("regional_internet_registry", "registry")):
                if value := attrs.get(key):
                    result.add(label, value, source="virustotal")
                    if key == "as_owner":
                        self._as_owner = str(value)
        else:
            if registrar := attrs.get("registrar"):
                result.add("registrar", registrar, source="virustotal")
            if created := attrs.get("creation_date"):
                result.add("domain created", _stamp(created), source="virustotal")

        # JARM is a TLS-stack fingerprint: two hosts sharing one are usually
        # running the same server software, which is a real pivot on Shodan.
        if jarm := attrs.get("jarm"):
            result.add("JARM fingerprint", jarm, source="virustotal",
                       url=f"https://www.shodan.io/search?query=ssl.jarm%3A{jarm}",
                       extra={"pivot": "shodan ssl.jarm"})

        cert = attrs.get("last_https_certificate")
        if isinstance(cert, dict):
            subject_cn = (cert.get("subject") or {}).get("CN")
            issuer = (cert.get("issuer") or {}).get("O")
            if subject_cn:
                self._cert_cn = str(subject_cn)
                result.add("TLS certificate", f"CN={subject_cn}"
                           + (f", issued by {issuer}" if issuer else ""),
                           source="virustotal")
            for alt in (cert.get("extensions") or {}).get("subject_alternative_name", [])[:25]:
                if isinstance(alt, str) and "." in alt and not alt.startswith("*"):
                    result.entity(EntityType.DOMAIN, alt, relation="cert-name",
                                  evidence="cert-san",
                                  detail="SAN on the TLS certificate")

    def _resolutions(self, kind: str, subject: str, is_ip: bool, result: ScanResult) -> None:
        """Passive DNS: what else VT has seen on this IP, or for this domain."""
        data = self.http.get_json(
            f"{API}/{kind}/{subject}/resolutions?limit=40",
            headers={"x-apikey": self.config.key("virustotal") or "",
                     "Accept": "application/json"},
        )
        rows = (data or {}).get("data") if isinstance(data, dict) else None
        if not isinstance(rows, list) or not rows:
            return

        seen: list[str] = []
        #: When VirusTotal last saw each resolution. A passive-DNS answer is a
        #: statement about the past, and the graph needs the date to say how
        #: far in the past - a name that pointed here in 2018 is not evidence
        #: that it points here now, and scoring it as though it were is how a
        #: run assembles a picture of somebody's former hosting neighbours.
        when: dict[str, float] = {}
        for row in rows:
            attrs = row.get("attributes") if isinstance(row, dict) else None
            if not isinstance(attrs, dict):
                continue
            value = attrs.get("host_name") if is_ip else attrs.get("ip_address")
            if not value or value in seen:
                continue
            seen.append(str(value))
            date = attrs.get("date")
            if isinstance(date, (int, float)) and date > 0:
                when[str(value)] = float(date)

        if not seen:
            return

        # Co-location on shared infrastructure is not a lead worth spending a
        # scan on. An anycast edge address answers for tens of thousands of
        # unrelated sites, and following its neighbours turned one scan of a
        # jeweller's website into forty-five pivots at cigar.cafe and
        # 2026.fragile.ventures. The finding stays - "this site is on Vercel
        # with many others" is true and sometimes useful - but it stops
        # generating work.
        verdict = judge_host(
            cohosted=len(seen) if is_ip else 0,
            as_owner=self._as_owner, ptr=self._ptr, cert_cn=self._cert_cn,
        ) if is_ip else SharedVerdict(False)

        label = "co-hosted domains" if is_ip else "historic IPs"
        extra = {"count": len(seen)}
        if verdict:
            extra["shared_hosting"] = verdict.reason
            extra["note"] = ("shared infrastructure: these names are "
                             "neighbours, not relations, and are not followed")
        else:
            extra["note"] = ("co-location is a lead, not a link - corroborate "
                             "before treating these as related")
        result.add(
            label,
            seen[:SAMPLE] if verdict else seen[:40],
            source="virustotal-passivedns",
            severity=Severity.INFO if verdict else Severity.NOTABLE,
            confidence=Confidence.POSSIBLE if verdict else Confidence.LIKELY,
            extra=extra,
        )
        if verdict:
            return

        for value in seen[:15]:
            age = when.get(value)
            detail = "VirusTotal passive DNS - co-location is a lead, not a link"
            if age:
                detail += f" (last seen {_stamp(age)})"
            result.entity(
                EntityType.DOMAIN if is_ip else EntityType.IP, value,
                relation="passive-dns", evidence="passive-dns",
                detail=detail, observed_at=age,
            )
