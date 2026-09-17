"""IP address intelligence.

Nothing here connects to the address itself. Geolocation, ASN, reverse DNS and
the Shodan InternetDB summary are all third-party lookups, so this whole module
is safe under ``--passive`` - the target never sees a packet from you.
"""

from __future__ import annotations

import ipaddress

from ..core import dns as dnsmod
from ..core.entities import EntityType
from ..core.models import Confidence, ScanResult, Severity, TargetType
from ..core.registry import Module, register


@register
class IpModule(Module):
    name = "ip"
    title = "IP geolocation and network"
    description = "Geo, ASN, hosting provider, reverse DNS, proxy/VPN flags."
    accepts = frozenset({TargetType.IP})

    def run(self, target: str, result: ScanResult) -> None:
        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            result.error("not an IP address")
            return

        if addr.is_private or addr.is_loopback or addr.is_link_local:
            result.add("scope", f"{target} is not routable on the public internet",
                       source="parse", severity=Severity.NOTABLE)
            return

        # ip-api's free tier is HTTP-only and rate-limited to 45 req/min.
        fields = "status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
        data = self.http.get_json(f"http://ip-api.com/json/{target}?fields={fields}")
        if isinstance(data, dict) and data.get("status") == "success":
            loc = ", ".join(x for x in (data.get("city"), data.get("regionName"),
                                        data.get("country")) if x)
            result.add("location", loc or "unknown", source="ip-api",
                       confidence=Confidence.LIKELY)
            if data.get("lat") is not None:
                result.add("coordinates", f"{data['lat']}, {data['lon']}", source="ip-api",
                           url=f"https://www.openstreetmap.org/?mlat={data['lat']}&mlon={data['lon']}#map=10/{data['lat']}/{data['lon']}",
                           confidence=Confidence.POSSIBLE,
                           extra={"note": "IP geolocation is city-level at best"})
            for key, label in (("timezone", "timezone"), ("isp", "ISP"),
                               ("org", "organisation"), ("as", "ASN"), ("zip", "postal code")):
                if value := data.get(key):
                    result.add(label, value, source="ip-api")
            flags = [k for k in ("mobile", "proxy", "hosting") if data.get(k)]
            if flags:
                result.add("network type", ", ".join(flags), source="ip-api",
                           severity=Severity.NOTABLE,
                           extra={"note": "proxy/hosting means the geo is the datacentre, not a person"})
        else:
            result.error("ip-api lookup failed")

        ptr = dnsmod.resolve(self.http, _reverse_name(addr), "PTR")
        if ptr:
            names = sorted({p.rstrip(".") for p in ptr})
            result.add("reverse DNS", names, source="doh")
            for n in names[:5]:
                result.entity(EntityType.DOMAIN, n, relation="reverse-dns",
                              evidence="reverse-dns", detail="PTR record")

        self._internetdb(target, result)
        self._rdap(target, result)

    def _internetdb(self, ip: str, result: ScanResult) -> None:
        """Shodan's free, keyless summary of what they last saw on this host."""
        data = self.http.get_json(f"https://internetdb.shodan.io/{ip}")
        if not isinstance(data, dict) or "ip" not in data:
            return
        if ports := data.get("ports"):
            result.add("open ports (last Shodan scan)", sorted(ports), source="shodan-internetdb",
                       confidence=Confidence.LIKELY, severity=Severity.NOTABLE,
                       url=f"https://www.shodan.io/host/{ip}",
                       extra={"note": "historic observation, not a live scan"})
        if hostnames := data.get("hostnames"):
            result.add("hostnames", sorted(hostnames), source="shodan-internetdb")
            for h in sorted(hostnames)[:10]:
                result.entity(EntityType.DOMAIN, h, relation="hosted-name",
                              evidence="reverse-dns",
                              detail="hostname seen by Shodan InternetDB")
        if cpes := data.get("cpes"):
            result.add("software (CPE)", sorted(cpes), source="shodan-internetdb",
                       confidence=Confidence.LIKELY)
        if vulns := data.get("vulns"):
            result.add("CVEs attributed by Shodan", sorted(vulns), source="shodan-internetdb",
                       severity=Severity.HIGH, confidence=Confidence.POSSIBLE,
                       extra={"note": "version-inferred, not verified by exploitation"})
        if tags := data.get("tags"):
            result.add("tags", sorted(tags), source="shodan-internetdb")

    def _rdap(self, ip: str, result: ScanResult) -> None:
        data = self.http.get_json(f"https://rdap.org/ip/{ip}")
        if not isinstance(data, dict):
            return
        if name := data.get("name"):
            result.add("netblock name", name, source="rdap")
        if cidr := data.get("handle"):
            result.add("netblock", cidr, source="rdap")
        if start := data.get("startAddress"):
            result.add("range", f"{start} - {data.get('endAddress', '?')}", source="rdap")
        if country := data.get("country"):
            result.add("registry country", country, source="rdap")
        # Registries nest entities and repeat the same abuse address across
        # several of them (APNIC lists it twice for 1.1.1.1), so collect first.
        abuse: set[str] = set()
        for ent in data.get("entities", []) or []:
            if "abuse" not in ",".join(ent.get("roles", [])):
                continue
            for item in ent.get("vcardArray", [None, []])[1] or []:
                if isinstance(item, list) and len(item) >= 4 and item[0] == "email":
                    abuse.add(str(item[3]))
        for address in sorted(abuse):
            result.add("abuse contact", address, source="rdap", severity=Severity.NOTABLE)


def _reverse_name(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    return addr.reverse_pointer


@register
class AbuseIpModule(Module):
    name = "abuseipdb"
    title = "AbuseIPDB reputation"
    description = "Abuse confidence score and recent report categories."
    accepts = frozenset({TargetType.IP})
    requires_key = "abuseipdb"

    def run(self, target: str, result: ScanResult) -> None:
        data = self.http.get_json(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={target}&maxAgeInDays=90",
            headers={"Key": self.config.key("abuseipdb") or "", "Accept": "application/json"},
        )
        payload = (data or {}).get("data") if isinstance(data, dict) else None
        if not payload:
            result.error("AbuseIPDB returned no data")
            return
        score = payload.get("abuseConfidenceScore", 0)
        result.add(
            "abuse confidence",
            f"{score}%",
            source="abuseipdb",
            severity=Severity.HIGH if score >= 50 else Severity.INFO,
            url=f"https://www.abuseipdb.com/check/{target}",
        )
        for key, label in (("totalReports", "reports (90d)"), ("usageType", "usage type"),
                           ("domain", "domain"), ("isTor", "Tor exit node")):
            if (value := payload.get(key)) not in (None, "", False):
                result.add(label, value, source="abuseipdb")
