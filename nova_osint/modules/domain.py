"""Domain intelligence: registration, DNS, mail posture, subdomains.

Split into four registered modules so a user can run just the part they need
(``--only dns``) and so one slow source cannot stall the rest.

Everything here is passive except ``subdomains``' optional resolution step:
certificate transparency and passive-DNS aggregators are third parties, but
confirming which of the discovered hosts are live does touch the target's
nameservers. That step runs only outside ``--passive``.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from ..core import dns as dnsmod
from ..core.http import hostname_of
from ..core.models import Confidence, ScanResult, Severity, TargetType
from ..core.registry import Module, register

RDAP_BOOTSTRAP = "https://rdap.org/domain/{domain}"


def _fmt_date(value: str) -> str:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - dt).days
        return f"{dt.date().isoformat()} ({abs(age)} days {'ago' if age >= 0 else 'from now'})"
    except Exception:
        return value


@register
class WhoisModule(Module):
    name = "whois"
    title = "Registration (RDAP)"
    description = "Registrar, key dates, status flags and nameservers via RDAP."
    accepts = frozenset({TargetType.DOMAIN, TargetType.URL})

    def run(self, target: str, result: ScanResult) -> None:
        queried = hostname_of(target)
        data, domain = self._lookup(queried)
        if data is None:
            result.error(f"no RDAP record found for {queried} or any parent domain")
            return
        if domain != queried:
            # Registries only hold the registrable domain; www.foo.co.uk has no
            # record of its own, so we walk up until one answers.
            result.add("registrable domain", domain, source="rdap",
                       extra={"queried": queried})

        result.add("domain", data.get("ldhName", domain), source="rdap")
        if handle := data.get("handle"):
            result.add("registry id", handle, source="rdap")

        for event in data.get("events", []):
            action = str(event.get("eventAction", "")).replace(" ", "-")
            if action in {"registration", "expiration", "last-changed", "last-update-of-rdap-database"}:
                label = {"registration": "registered", "expiration": "expires",
                         "last-changed": "last changed"}.get(action, action)
                if action == "last-update-of-rdap-database":
                    continue
                sev = Severity.INFO
                # A domain registered in the last month is worth flagging: it is
                # the single strongest signal in phishing triage.
                if action == "registration":
                    try:
                        dt = datetime.fromisoformat(
                            str(event.get("eventDate")).replace("Z", "+00:00")
                        )
                        if (datetime.now(timezone.utc) - dt).days < 30:
                            sev = Severity.HIGH
                    except Exception:
                        pass
                result.add(label, _fmt_date(str(event.get("eventDate"))), source="rdap", severity=sev)

        flags = list(data.get("status", []))
        if flags:
            locked = any(("lock" in f.lower() or "prohibited" in f.lower()) for f in flags)
            result.add(
                "status",
                ", ".join(flags),
                source="rdap",
                severity=Severity.INFO if locked else Severity.NOTABLE,
            )

        for ent in data.get("entities", []):
            roles = ",".join(ent.get("roles", []))
            name = _vcard_field(ent, "fn") or ent.get("handle", "")
            if name and roles:
                result.add(f"entity ({roles})", name, source="rdap")
            if email := _vcard_field(ent, "email"):
                result.add(f"contact email ({roles})", email, source="rdap",
                           severity=Severity.NOTABLE)
                result.pivot(email, TargetType.EMAIL, f"RDAP {roles} contact")

        ns = sorted({n.get("ldhName", "").lower() for n in data.get("nameservers", []) if n.get("ldhName")})
        if ns:
            result.add("nameservers", ns, source="rdap")
        if (dnssec := data.get("secureDNS")) is not None:
            signed = bool(dnssec.get("delegationSigned"))
            result.add(
                "DNSSEC",
                "signed" if signed else "not signed",
                source="rdap",
                severity=Severity.INFO if signed else Severity.NOTABLE,
            )


    def _lookup(self, host: str) -> tuple[dict | None, str]:
        """Try the host, then each parent, until a registry answers.

        Stops before the bare TLD: ``rdap.org`` will happily return the record
        for ``com`` itself, which is never what the user meant.
        """
        labels = host.split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            resp = self.http.get(RDAP_BOOTSTRAP.format(domain=candidate))
            data = resp.json()
            if isinstance(data, dict) and data.get("objectClassName") == "domain":
                return data, candidate
        return None, host


def _vcard_field(entity: dict, field: str) -> str | None:
    for item in entity.get("vcardArray", [None, []])[1] or []:
        if isinstance(item, list) and len(item) >= 4 and item[0] == field:
            value = item[3]
            return value if isinstance(value, str) else str(value)
    return None


@register
class DnsModule(Module):
    name = "dns"
    title = "DNS records"
    description = "A/AAAA/MX/NS/TXT/SOA/CAA over DNS-over-HTTPS."
    accepts = frozenset({TargetType.DOMAIN, TargetType.URL})

    RTYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA")

    def run(self, target: str, result: ScanResult) -> None:
        domain = hostname_of(target)
        pairs = self.http.map(
            lambda rt: (rt, dnsmod.resolve(self.http, domain, rt)), self.RTYPES
        )
        for pair in pairs:
            if not pair:
                continue
            rtype, answers = pair
            if not answers:
                continue
            result.add(rtype, sorted(set(answers)), source="doh")
            if rtype in ("A", "AAAA"):
                for ip in answers:
                    result.pivot(ip, TargetType.IP, f"{rtype} record for {domain}")

        if not any(p and p[1] for p in pairs):
            result.error(f"{domain} does not resolve")


@register
class MailPostureModule(Module):
    name = "mailsec"
    title = "Mail security posture"
    description = "SPF, DMARC, DKIM selectors, MX provider and BIMI."
    accepts = frozenset({TargetType.DOMAIN, TargetType.EMAIL, TargetType.URL})

    #: Selectors worth probing - these cover the major ESPs.
    SELECTORS = (
        "default", "google", "selector1", "selector2", "k1", "k2", "mail",
        "dkim", "s1", "s2", "mandrill", "zoho", "protonmail", "fm1", "everlytickey1",
    )

    def run(self, target: str, result: ScanResult) -> None:
        domain = target.split("@")[-1] if "@" in target else hostname_of(target)

        mx = dnsmod.resolve(self.http, domain, "MX")
        if mx:
            hosts = sorted({m.split()[-1].rstrip(".").lower() for m in mx if m.split()})
            result.add("MX", hosts, source="doh")
            result.add("mail provider", _guess_provider(hosts), source="heuristic",
                       confidence=Confidence.LIKELY)
        else:
            result.add("MX", "none - domain cannot receive mail", source="doh",
                       severity=Severity.NOTABLE)

        txt = dnsmod.resolve(self.http, domain, "TXT")
        spf = [t for t in txt if t.lower().startswith("v=spf1")]
        if spf:
            record = spf[0]
            strict = record.rstrip().endswith(("-all", "~all"))
            result.add(
                "SPF",
                record,
                source="doh",
                severity=Severity.INFO if strict else Severity.HIGH,
                extra={"policy": record.split()[-1] if record.split() else ""},
            )
            if not strict:
                result.add("SPF weakness", "no -all/~all terminator: spoofable",
                           source="analysis", severity=Severity.HIGH)
        else:
            result.add("SPF", "missing", source="doh", severity=Severity.HIGH)

        dmarc = dnsmod.resolve(self.http, f"_dmarc.{domain}", "TXT")
        policy_rec = next((d for d in dmarc if d.lower().startswith("v=dmarc1")), None)
        if policy_rec:
            m = re.search(r"\bp=(\w+)", policy_rec)
            policy = m.group(1).lower() if m else "unknown"
            result.add(
                "DMARC",
                policy_rec,
                source="doh",
                severity=Severity.INFO if policy in ("reject", "quarantine") else Severity.HIGH,
                extra={"policy": policy},
            )
            if policy == "none":
                result.add("DMARC weakness", "p=none: monitoring only, nothing is blocked",
                           source="analysis", severity=Severity.HIGH)
            for rua in re.findall(r"mailto:([^,;\s]+)", policy_rec):
                result.pivot(rua, TargetType.EMAIL, "DMARC report address")
        else:
            result.add("DMARC", "missing", source="doh", severity=Severity.HIGH)

        # Non-existent selectors simply NXDOMAIN, so this is cheap and quiet.
        found = self.http.map(
            lambda s: (s, dnsmod.resolve(self.http, f"{s}._domainkey.{domain}", "TXT")),
            self.SELECTORS,
        )
        live, revoked = _split_dkim(found)
        if live:
            result.add("DKIM selectors", live, source="doh")
        if revoked:
            # A record that exists but carries an empty p= tag is the RFC 6376
            # way of saying "this key is revoked". Counting it as a working
            # selector is a false positive, and some domains (example.com among
            # them) answer every selector this way.
            result.add(
                "DKIM selectors with no key",
                revoked,
                source="doh",
                severity=Severity.NOTABLE,
                extra={"note": "v=DKIM1 with an empty p= tag means the key is revoked "
                               "(RFC 6376 section 3.6.1), not that DKIM is in use"},
            )

        if bimi := dnsmod.resolve(self.http, f"default._bimi.{domain}", "TXT"):
            result.add("BIMI", bimi[0], source="doh")


def _split_dkim(pairs: list[tuple[str, list[str]] | None]) -> tuple[list[str], list[str]]:
    """Sort probed selectors into ``(has a key, exists but revoked)``.

    A selector only counts as live when its record carries a non-empty ``p=``
    public key. Everything else either does not exist or explicitly says the
    key is gone.
    """
    live: list[str] = []
    revoked: list[str] = []
    for pair in pairs:
        if not pair:
            continue
        selector, records = pair
        record = next((r for r in records if "v=dkim1" in r.lower()), None)
        if record is None:
            continue
        key = re.search(r"\bp=\s*([A-Za-z0-9+/=]*)", record)
        (live if key and key.group(1) else revoked).append(selector)
    return live, revoked


def _guess_provider(mx_hosts: list[str]) -> str:
    table = {
        "google": "Google Workspace",
        "outlook": "Microsoft 365",
        "protection.outlook": "Microsoft 365",
        "zoho": "Zoho Mail",
        "proton": "Proton Mail",
        "mailgun": "Mailgun",
        "sendgrid": "SendGrid",
        "amazonaws": "Amazon SES/WorkMail",
        "mimecast": "Mimecast",
        "pphosted": "Proofpoint",
        "barracuda": "Barracuda",
        "yandex": "Yandex",
        "fastmail": "Fastmail",
        "messagingengine": "Fastmail",
        "secureserver": "GoDaddy",
        "improvmx": "ImprovMX",
        "titan": "Titan",
    }
    joined = " ".join(mx_hosts)
    for needle, label in table.items():
        if needle in joined:
            return label
    return "self-hosted or unrecognised"


def _under(name: str, domain: str) -> bool:
    """Is ``name`` the domain itself or something beneath it?

    ``endswith(domain)`` is the obvious test and it is wrong: it accepts
    ``m.testexample.com`` as a subdomain of ``example.com``, because the label
    boundary is not part of a suffix match. That false positive is quiet - it
    looks exactly like a real subdomain in a list of two hundred - and it is a
    third party's host, so following it widens the scan onto someone unrelated.
    """
    name = str(name).strip().lower().rstrip(".").lstrip("*.")
    domain = domain.strip().lower().rstrip(".")
    return bool(name) and (name == domain or name.endswith("." + domain))


@register
class SubdomainModule(Module):
    name = "subdomains"
    title = "Subdomain discovery"
    description = "Certificate transparency plus passive DNS, optionally resolved."
    accepts = frozenset({TargetType.DOMAIN, TargetType.URL})
    slow = True

    def run(self, target: str, result: ScanResult) -> None:
        domain = hostname_of(target)
        sources = {
            "crt.sh": self._crtsh,
            "certspotter": self._certspotter,
            "hackertarget": self._hackertarget,
            "rapiddns": self._rapiddns,
        }
        gathered = self.http.map(lambda kv: (kv[0], kv[1](domain)), list(sources.items()))

        names: dict[str, set[str]] = {}
        for pair in gathered:
            if not pair:
                continue
            src, found = pair
            if found is None:
                result.error(f"{src} unavailable")
                continue
            result.add(f"source: {src}", f"{len(found)} name(s)", source=src)
            for n in found:
                names.setdefault(n, set()).add(src)

        # Wildcard entries from CT are noise as hostnames but tell you a wildcard
        # cert exists, which is worth its own line.
        wildcards = sorted(n for n in names if n.startswith("*."))
        hosts = sorted(n for n in names if not n.startswith("*.") and n != domain)
        if wildcards:
            result.add("wildcard certificates", wildcards, source="ct",
                       severity=Severity.NOTABLE)
        if not hosts:
            result.add("subdomains", "none found", source="ct")
            return

        if self.config.passive_only:
            result.add(
                "subdomains (unresolved)",
                hosts,
                source="ct+passivedns",
                confidence=Confidence.POSSIBLE,
                severity=Severity.NOTABLE,
                extra={"count": len(hosts)},
            )
            return

        capped = hosts[: self.config.max_sites] if self.config.max_sites else hosts
        live_flags = self.http.map(lambda h: (h, dnsmod.resolves(self.http, h)), capped)
        live = sorted(h for pair in live_flags if pair for h, ok in [pair] if ok)
        dead = [h for h in capped if h not in set(live)]

        result.add(
            "live subdomains",
            live,
            source="ct+dns",
            severity=Severity.NOTABLE,
            extra={"count": len(live), "total_seen": len(hosts)},
        )
        if dead:
            # Historical names that no longer resolve are the takeover candidates.
            result.add(
                "historic (no A/AAAA)",
                dead,
                source="ct",
                confidence=Confidence.POSSIBLE,
                extra={"count": len(dead)},
            )
        for h in live[:25]:
            result.pivot(h, TargetType.DOMAIN, "live subdomain")

    # ------------------------------------------------------------------ sources

    def _crtsh(self, domain: str) -> set[str] | None:
        out: set[str] = set()
        for q in (f"%.{domain}", domain):
            resp = self.http.get(
                f"https://crt.sh/?q={self._q(q)}&output=json", timeout=45
            )
            rows = resp.json()
            if not isinstance(rows, list):
                continue
            for row in rows:
                for name in str(row.get("name_value", "")).splitlines():
                    if _under(name, domain):
                        out.add(name.strip().lower().rstrip("."))
        return out or None

    def _certspotter(self, domain: str) -> set[str] | None:
        url = (
            "https://api.certspotter.com/v1/issuances"
            f"?domain={domain}&include_subdomains=true&expand=dns_names"
        )
        rows = self.http.get(url, timeout=30).json()
        if not isinstance(rows, list):
            return None
        out = set()
        for row in rows:
            for name in row.get("dns_names", []):
                if _under(name, domain):
                    out.add(str(name).strip().lower().rstrip("."))
        return out

    def _hackertarget(self, domain: str) -> set[str] | None:
        resp = self.http.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        if not resp.ok or "error" in resp.text.lower() or "API count exceeded" in resp.text:
            return None
        out = set()
        for line in resp.text.splitlines():
            host = line.split(",")[0].strip().lower()
            if _under(host, domain):
                out.add(host)
        return out

    def _rapiddns(self, domain: str) -> set[str] | None:
        resp = self.http.get(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=30)
        if not resp.ok:
            return None
        out = {
            m.lower()
            for m in re.findall(rf"<td>([A-Za-z0-9_.-]+\.{re.escape(domain)})</td>", resp.text)
        }
        return out

    @staticmethod
    def _q(value: str) -> str:
        import urllib.parse

        return urllib.parse.quote(value, safe="")
