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
from ..core.entities import EntityType
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
                result.entity(EntityType.EMAIL, email, relation="contact",
                              evidence="rdap-contact",
                              detail=f"RDAP {roles} contact")

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
                    result.entity(EntityType.IP, ip, relation="resolves-to",
                                  evidence="dns-a",
                                  detail=f"{rtype} record for {domain}")

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
            # rua and ruf are different tags carrying different things, and
            # scooping every mailto: out of the whole record labelled them all
            # "rua". ruf is the one that matters more: a forensic address
            # receives failed messages themselves - headers, sometimes the body
            # - so whoever reads it sees mail sent to the domain. Reporting
            # that as an aggregate-report address understates it.
            for tag, evidence, detail in (
                ("rua", "dmarc-rua", "address in the DMARC rua tag "
                                     "(aggregate reports)"),
                ("ruf", "dmarc-ruf", "address in the DMARC ruf tag "
                                     "(forensic reports: receives failed "
                                     "messages, headers and all)"),
            ):
                m_tag = re.search(rf"\b{tag}=([^;]+)", policy_rec)
                if not m_tag:
                    continue
                for addr in re.findall(r"mailto:([^,;\s]+)", m_tag.group(1)):
                    result.entity(EntityType.EMAIL, addr,
                                  relation="dmarc-reports-to",
                                  evidence=evidence, detail=detail)
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


#: Labels: letters, digits, hyphens - and a leading underscore for service
#: records (``_dmarc``, ``_domainkey``), which are names but not hosts.
_LABEL = re.compile(r"^_?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def normalise_host(name: str, domain: str) -> str:
    """One normaliser for every source, or ``""`` if the name is unusable.

    Strip, drop the trailing dot, lowercase, drop ``*.``/``•.`` prefixes,
    IDNA-encode, refuse IPs, enforce 253/63 lengths and the label alphabet,
    and keep only the domain itself or a dot-bounded name under it.
    """
    n = str(name or "").strip().lower().rstrip(".")
    while n.startswith(("*.", "•.", "•")):
        n = n[2:] if n.startswith(("*.", "•.")) else n[1:]
    if not n or _IPV4.match(n):
        return ""
    try:
        n = n.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    if len(n) > 253 or not _under(n, domain):
        return ""
    if not all(_LABEL.match(label) for label in n.split(".")):
        return ""
    return n


@register
class SubdomainModule(Module):
    """Subdomains from nine free, keyless sources, then checked against DNS.

    Three rules from subfinder/Amass/theHarvester that this used to lack:

    * **A source that failed is not a source that found nothing.** crt.sh
      spends much of 2026 answering 502; HackerTarget answers *200* with "API
      count exceeded". Each source now reports ok / empty / limited / failed.
    * **Wildcard DNS makes every name "live".** Before calling anything live,
      three random labels are resolved at the apex and at each parent level a
      candidate sits under; a name whose answers fall inside that wildcard
      set is "wildcard-only", not live.
    * **One source is a lead; several are a corroboration.** Each name
      carries the list of sources that reported it.
    """

    name = "subdomains"
    title = "Subdomain discovery"
    description = "Certificate transparency plus passive DNS, optionally resolved."
    accepts = frozenset({TargetType.DOMAIN, TargetType.URL})
    slow = True

    SOURCES = ("crt.sh", "certspotter", "crt.name", "shodan-ct", "thc",
               "anubis", "hackertarget", "rapiddns", "urlscan")

    def run(self, target: str, result: ScanResult) -> None:
        domain = hostname_of(target)
        fetchers = {src: getattr(self, "_" + src.replace(".", "").replace("-", ""))
                    for src in self.SOURCES}
        gathered = self.http.map(lambda kv: (kv[0], self._safe(kv[1], domain)),
                                 list(fetchers.items()))

        names: dict[str, set[str]] = {}
        status: dict[str, str] = {}
        wildcard_certs: set[str] = set()
        for pair in gathered:
            if not pair:
                continue
            src, (state, found) = pair
            status[src] = state
            for raw in found:
                n = normalise_host(raw, domain)
                if n:
                    names.setdefault(n, set()).add(src)
                    # A wildcard certificate is not a host, but it is a fact
                    # worth its own line: anything under it can be served.
                    if str(raw).strip().startswith("*."):
                        wildcard_certs.add("*." + n)
        if wildcard_certs:
            result.add("wildcard certificates", sorted(wildcard_certs), source="ct",
                       severity=Severity.NOTABLE)
        answered = [s for s, st in status.items() if st in ("ok", "empty")]
        failed = {s: status.get(s, "failed") for s in self.SOURCES
                  if status.get(s, "failed") not in ("ok", "empty")}
        result.add("sources", {s: status.get(s, "failed") for s in self.SOURCES},
                   source="subdomains",
                   extra={"answered": len(answered), "failed": failed})
        if failed:
            result.error("subdomain sources not answering: " + ", ".join(
                f"{s} ({st})" for s, st in sorted(failed.items())))

        services = sorted(n for n in names
                          if any(lb.startswith("_") for lb in n.split(".")))
        hosts = sorted(n for n in names if n != domain and n not in services)
        if services:
            result.add("service names (not hosts)", services[:50],
                       source="ct+passivedns", extra={"count": len(services)})
        if not hosts:
            result.add("subdomains", "none found" if answered else
                       "unknown - no source answered", source="ct+passivedns")
            return

        sources_of = {h: sorted(names[h]) for h in hosts}
        corroborated = [h for h in hosts if len(names[h]) >= 2]

        if self.config.passive_only:
            result.add(
                "subdomains (unresolved)", hosts, source="ct+passivedns",
                confidence=Confidence.POSSIBLE, severity=Severity.NOTABLE,
                extra={"count": len(hosts), "corroborated": len(corroborated),
                       "sources": {h: sources_of[h] for h in hosts[:200]}})
            return

        capped = hosts[: self.config.max_sites] if self.config.max_sites else hosts
        wild = self._wildcards(domain, capped)
        if wild:
            result.add("wildcard DNS", sorted(wild), source="dns",
                       severity=Severity.NOTABLE,
                       extra={"note": "random names resolve here, so a name "
                                      "under these zones resolving proves nothing"})
        answers = self.http.map(lambda h: (h, self._answers(h)), capped)
        live: list[str] = []
        wildcard_only: list[str] = []
        dead: list[str] = []
        for pair in answers:
            if not pair:
                continue
            h, got = pair
            if not got:
                dead.append(h)
                continue
            zone_set = next((wild[z] for z in _parents(h, domain) if z in wild), None)
            if zone_set is not None and got <= zone_set:
                wildcard_only.append(h)
            else:
                live.append(h)
        live.sort()

        result.add(
            "live subdomains", live, source="ct+dns", severity=Severity.NOTABLE,
            extra={"count": len(live), "total_seen": len(hosts),
                   "corroborated": len([h for h in live if len(names[h]) >= 2]),
                   "sources": {h: sources_of[h] for h in live[:200]}})
        if wildcard_only:
            result.add("resolve only through the wildcard", sorted(wildcard_only),
                       source="ct+dns", confidence=Confidence.POSSIBLE,
                       extra={"count": len(wildcard_only)})
        if dead:
            # Historical names that no longer resolve are the takeover candidates.
            result.add("historic (no A/AAAA)", sorted(dead), source="ct",
                       confidence=Confidence.POSSIBLE, extra={"count": len(dead)})
        for h in live[:25]:
            result.entity(EntityType.DOMAIN, h, relation="subdomain-of",
                          evidence="subdomain-of",
                          detail=f"resolves; reported by {', '.join(sources_of[h])}")

    # ------------------------------------------------------------- wildcards

    def _answers(self, host: str) -> frozenset[str]:
        got = set(dnsmod.resolve(self.http, host, "A"))
        got |= set(dnsmod.resolve(self.http, host, "AAAA"))
        return frozenset(a.rstrip(".").lower() for a in got)

    def _wildcards(self, domain: str, hosts: list[str]) -> dict[str, frozenset[str]]:
        """``{zone: answers}`` for every zone that answers random names.

        Amass's method: every level between the apex and a candidate, three
        random labels each. A round-robin wildcard hands out different
        addresses per query, so the union of the three is the wildcard's set.
        """
        zones = {domain}
        for h in hosts:
            zones.update(_parents(h, domain))
        chosen = sorted(zones, key=lambda z: (len(z), z))[:40]

        def probe(zone: str) -> tuple[str, frozenset[str] | None]:
            sets = [self._answers(f"{_rand_label()}.{zone}") for _ in range(3)]
            if all(sets):
                return zone, frozenset().union(*sets)
            return zone, None

        out: dict[str, frozenset[str]] = {}
        for pair in self.http.map(probe, chosen):
            if pair and pair[1]:
                out[pair[0]] = pair[1]
        return out

    # ---------------------------------------------------------------- sources

    @staticmethod
    def _safe(fn, domain: str) -> tuple[str, set[str]]:  # type: ignore[no-untyped-def]
        try:
            got = fn(domain)
        except Exception as exc:  # noqa: BLE001 - one source must not end the module
            return f"failed ({type(exc).__name__})", set()
        if isinstance(got, tuple):
            return got
        if got is None:
            return "failed", set()
        return ("ok" if got else "empty"), set(got)

    @staticmethod
    def _state(resp) -> str:  # type: ignore[no-untyped-def]
        if resp.status == 429:
            return "limited"
        if not resp.ok:
            return f"failed ({resp.status or resp.error or 'no answer'})"
        return ""

    def _crtsh(self, domain: str):  # type: ignore[no-untyped-def]
        out: set[str] = set()
        resp = self.http.get(f"https://crt.sh/?q={self._q('%.' + domain)}&output=json",
                             timeout=45)
        if bad := self._state(resp):
            return bad, out
        rows = resp.json()
        if not isinstance(rows, list):
            return "failed (not JSON)", out
        for row in rows:
            for name in str(row.get("name_value", "")).splitlines():
                out.add(name)
        return ("ok" if out else "empty"), out

    def _certspotter(self, domain: str):  # type: ignore[no-untyped-def]
        out: set[str] = set()
        after = ""
        for _page in range(5):
            url = ("https://api.certspotter.com/v1/issuances"
                   f"?domain={domain}&include_subdomains=true&expand=dns_names"
                   + (f"&after={after}" if after else ""))
            resp = self.http.get(url, timeout=30)
            rows = resp.json()
            if isinstance(rows, dict) and rows.get("code") == "rate_limited":
                return ("ok" if out else "limited"), out
            if bad := self._state(resp):
                return ("ok" if out else bad), out
            if not isinstance(rows, list) or not rows:
                break
            for row in rows:
                out.update(str(n) for n in row.get("dns_names", []))
            after = str(rows[-1].get("id", ""))
            if len(rows) < 100 or not after:
                break
        return ("ok" if out else "empty"), out

    def _crtname(self, domain: str):  # type: ignore[no-untyped-def]
        resp = self.http.get(f"https://crt.name/v1/search?apex={domain}",
                             headers={"Accept": "text/plain"}, timeout=30)
        if bad := self._state(resp):
            return bad, set()
        out = {ln.strip() for ln in resp.text.splitlines() if ln.strip()}
        return ("ok" if out else "empty"), out

    def _shodanct(self, domain: str):  # type: ignore[no-untyped-def]
        resp = self.http.get(f"https://ctl.shodan.io/api/v1/domain/{domain}/hostnames",
                             timeout=30)
        if resp.status == 404:
            return "empty", set()
        if bad := self._state(resp):
            return bad, set()
        data = resp.json()
        out = {str(x) for x in data} if isinstance(data, list) else set()
        return ("ok" if out else "empty"), out

    def _thc(self, domain: str):  # type: ignore[no-untyped-def]
        resp = self.http.get(
            f"https://ip.thc.org/api/v1/subdomains/download?domain={domain}"
            "&limit=5000&hide_header=true", timeout=30)
        if bad := self._state(resp):
            return bad, set()
        out = {ln.strip().split(",")[0] for ln in resp.text.splitlines() if ln.strip()}
        return ("ok" if out else "empty"), out

    def _anubis(self, domain: str):  # type: ignore[no-untyped-def]
        resp = self.http.get(f"https://anubisdb.com/anubis/subdomains/{domain}",
                             timeout=30)
        if resp.status == 404:
            return "empty", set()
        if bad := self._state(resp):
            return bad, set()
        data = resp.json()
        out = {str(x) for x in data} if isinstance(data, list) else set()
        return ("ok" if out else "empty"), out

    def _hackertarget(self, domain: str):  # type: ignore[no-untyped-def]
        resp = self.http.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        if bad := self._state(resp):
            return bad, set()
        text = resp.text
        # Over quota it answers 200 with a sentence instead of data.
        if "api count exceeded" in text.lower():
            return "limited", set()
        if text.lower().startswith("error"):
            return ("empty" if "no records" in text.lower() else "failed"), set()
        out = {ln.split(",")[0].strip() for ln in text.splitlines() if "," in ln}
        return ("ok" if out else "empty"), out

    def _rapiddns(self, domain: str):  # type: ignore[no-untyped-def]
        resp = self.http.get(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=30)
        if bad := self._state(resp):
            return bad, set()
        out = set(re.findall(rf"<td>([A-Za-z0-9_.-]+\.{re.escape(domain)})</td>",
                             resp.text, flags=re.I))
        return ("ok" if out else "empty"), out

    def _urlscan(self, domain: str):  # type: ignore[no-untyped-def]
        # ``page.domain:`` - plain ``domain:`` also matches every third-party
        # host a page merely loaded something from.
        resp = self.http.get(
            f"https://urlscan.io/api/v1/search/?q=page.domain:{domain}&size=100",
            timeout=30)
        if bad := self._state(resp):
            return bad, set()
        data = resp.json()
        rows = data.get("results", []) if isinstance(data, dict) else []
        out = {str((r.get("page") or {}).get("domain")) for r in rows
               if (r.get("page") or {}).get("domain")}
        return ("ok" if out else "empty"), out

    @staticmethod
    def _q(value: str) -> str:
        import urllib.parse

        return urllib.parse.quote(value, safe="")


def _parents(host: str, domain: str) -> list[str]:
    """Zones strictly above ``host`` down to the apex, apex included."""
    labels = host.split(".")
    base = len(domain.split("."))
    return [".".join(labels[i:]) for i in range(1, len(labels) - base + 1)]


def _rand_label() -> str:
    import random
    import string

    return "nova" + "".join(random.choice(string.ascii_lowercase + string.digits)
                            for _ in range(14))


#: Filtering resolvers that answer DNS-over-HTTPS JSON with no key. Each runs
#: its own threat feed, so two of them blocking a name is two opinions.
_FILTERS = (
    ("Cloudflare malware filter",
     "https://security.cloudflare-dns.com/dns-query?name={name}&type=A",
     {"accept": "application/dns-json"}),
    ("AdGuard DNS",
     "https://dns.adguard-dns.com/resolve?name={name}&type=A", {}),
)
_SINKHOLES = frozenset({"0.0.0.0", "::", "94.140.14.35", "94.140.14.36"})


@register
class DnsFilterModule(Module):
    """Is this domain on a security DNS filter's blocklist?

    SpiderFoot's cheapest good idea: ask resolvers that refuse malicious
    names, and compare with what an ordinary resolver says. A block from one
    filter is one feed's opinion; it takes two to call a domain flagged. A
    clean answer means "on neither blocklist", which is all it means.
    """

    name = "dnsfilter"
    title = "DNS filter reputation"
    description = "Whether security DNS filters block the domain (keyless)."
    accepts = frozenset({TargetType.DOMAIN, TargetType.URL})

    def run(self, target: str, result: ScanResult) -> None:
        import urllib.parse

        domain = hostname_of(target)
        normal = dnsmod.resolve(self.http, domain, "A")
        if not normal:
            result.add("DNS filters", "not checked - the domain does not resolve",
                       source="dnsfilter")
            return

        blocked: list[str] = []
        answered = 0
        for label, template, headers in _FILTERS:
            resp = self.http.get(template.format(name=urllib.parse.quote(domain)),
                                 headers=headers, timeout=10)
            data = resp.json() if resp.ok else None
            if not isinstance(data, dict):
                continue
            answered += 1
            answers = {str(a.get("data", "")) for a in data.get("Answer") or []
                       if a.get("type") == 1}
            comment = " ".join(str(c) for c in data.get("Comment") or [])
            if (data.get("Status") == 3 or answers & _SINKHOLES
                    or "censored" in comment.lower() or "blocked" in comment.lower()):
                blocked.append(label)

        if not answered:
            result.error("no DNS filter answered")
            return
        if len(blocked) >= 2:
            result.add("DNS filter reputation", f"blocked by {', '.join(blocked)}",
                       source="dnsfilter", severity=Severity.HIGH,
                       confidence=Confidence.LIKELY,
                       extra={"note": "independent threat feeds both list this domain"})
        elif blocked:
            result.add("DNS filter reputation", f"blocked by {blocked[0]} only",
                       source="dnsfilter", severity=Severity.NOTABLE,
                       confidence=Confidence.POSSIBLE,
                       extra={"note": "one feed's opinion; the other resolves it normally"})
        else:
            result.add("DNS filter reputation",
                       f"not blocked by the {answered} filter(s) asked",
                       source="dnsfilter")
