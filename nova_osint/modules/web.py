"""Web surface: headers, exposed files, technology fingerprint, archive history.

These modules are *active* - they fetch pages from the target's own web server,
so a request shows up in its logs. They are skipped under ``--passive`` except
``wayback``, which only reads the Internet Archive.
"""

from __future__ import annotations

import base64
import re
import struct
import urllib.parse

from ..core.entities import EntityType
from ..core.http import hostname_of
from ..core.models import Confidence, ScanResult, Severity, TargetType
from ..core.registry import Module, register

#: Header -> what its absence means, for the posture table.
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS: browsers may fall back to plaintext",
    "content-security-policy": "no CSP: XSS has no second line of defence",
    "x-content-type-options": "MIME sniffing is allowed",
    "x-frame-options": "clickjacking not blocked (unless CSP frame-ancestors)",
    "referrer-policy": "full URLs leak to third parties",
    "permissions-policy": "no restriction on camera/mic/geolocation APIs",
}

#: Headers that hand out version information for free.
LEAKY_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator",
                 "x-drupal-cache", "x-runtime", "via")

TECH_SIGNATURES = (
    (r"wp-content|wp-includes", "WordPress"),
    (r"/_next/static", "Next.js"),
    (r"__NUXT__", "Nuxt"),
    (r"ng-version=", "Angular"),
    (r"data-reactroot|__REACT_DEVTOOLS", "React"),
    (r"Shopify\.theme|cdn\.shopify\.com", "Shopify"),
    (r"cdn\.squarespace\.com", "Squarespace"),
    (r"static\.parastorage\.com|wix\.com", "Wix"),
    (r"drupal-settings-json", "Drupal"),
    (r"/media/jui/|Joomla", "Joomla"),
    (r"cf-ray", "Cloudflare"),
    (r"webflow", "Webflow"),
    (r"gatsby", "Gatsby"),
    (r"vercel", "Vercel"),
)


def _base_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")
    return "https://" + target.strip("/")


def _reach(http, target: str):  # type: ignore[no-untyped-def]
    """Fetch the site, falling back to plaintext when TLS is not listening.

    Returns ``(response, base_url, https_ok)``. Plenty of real hosts - old
    internal boxes, redirect-only vhosts, scanme.nmap.org - answer on port 80
    and nothing on 443; treating that as "unreachable" loses the whole module.
    """
    base = _base_url(target)
    resp = http.get(base, follow_redirects=True)
    if resp.status != 0:
        return resp, base, base.startswith("https://")
    if base.startswith("https://"):
        fallback = "http://" + base[len("https://"):]
        alt = http.get(fallback, follow_redirects=True)
        if alt.status != 0:
            return alt, fallback, False
    return resp, base, False


@register
class HeadersModule(Module):
    name = "headers"
    title = "HTTP response and security headers"
    description = "Status chain, server banners, cookie flags, missing hardening headers."
    accepts = frozenset({TargetType.DOMAIN, TargetType.URL})
    active = True

    def run(self, target: str, result: ScanResult) -> None:
        resp, url, https_ok = _reach(self.http, target)
        if resp.status == 0:
            result.error(f"could not reach {url}: {resp.error}")
            return
        if not https_ok:
            result.add("HTTPS", "not available - served over plaintext HTTP",
                       source="http", severity=Severity.HIGH)

        result.add("final URL", resp.url, source="http",
                   severity=Severity.NOTABLE if resp.url.rstrip("/") != url else Severity.INFO)
        result.add("status", resp.status, source="http")
        if title := _title(resp.text):
            result.add("page title", title, source="http")

        for h in LEAKY_HEADERS:
            if value := resp.header(h):
                result.add(
                    f"banner: {h}",
                    value,
                    source="http",
                    severity=Severity.NOTABLE if re.search(r"\d+\.\d+", value) else Severity.INFO,
                )

        missing = [msg for h, msg in SECURITY_HEADERS.items() if not resp.header(h)]
        present = [h for h in SECURITY_HEADERS if resp.header(h)]
        if present:
            result.add("security headers present", present, source="http")
        if missing:
            result.add(
                "security headers missing",
                missing,
                source="analysis",
                severity=Severity.HIGH if len(missing) > 3 else Severity.NOTABLE,
            )

        cookies = [v for k, v in resp.headers.items() if k == "set-cookie"]
        for cookie in cookies:
            name = cookie.split("=", 1)[0]
            flags = [f for f in ("HttpOnly", "Secure", "SameSite") if f.lower() in cookie.lower()]
            weak = [f for f in ("HttpOnly", "Secure") if f not in flags]
            result.add(
                f"cookie: {name}",
                ", ".join(flags) or "no flags",
                source="http",
                severity=Severity.NOTABLE if weak else Severity.INFO,
            )

        tech = sorted({
            label for pattern, label in TECH_SIGNATURES
            if re.search(pattern, resp.text[:200_000], re.I)
            or re.search(pattern, " ".join(resp.headers), re.I)
        })
        if tech:
            result.add("technology", tech, source="fingerprint", confidence=Confidence.LIKELY)

        # A favicon hash is the standard pivot into Shodan/Censys for finding
        # other hosts running the same app, including staging boxes.
        fav = self.http.get(urllib.parse.urljoin(resp.url, "/favicon.ico"))
        if fav.ok and fav.body:
            h = _mmh3_b64(fav.body)
            result.add(
                "favicon hash (mmh3)",
                h,
                source="fingerprint",
                url=f"https://www.shodan.io/search?query=http.favicon.hash%3A{h}",
                extra={"pivot": "shodan http.favicon.hash"},
            )


def _title(html: str) -> str | None:
    m = re.search(r"<title[^>]*>(.*?)</title>", html[:100_000], re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:160] if m else None


def _mmh3_b64(data: bytes) -> int:
    """MurmurHash3 x86 32-bit of the base64-encoded body - Shodan's convention."""
    encoded = base64.encodebytes(data)
    return _murmur3_32(encoded)


def _murmur3_32(data: bytes, seed: int = 0) -> int:
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed
    rounded = (length & 0xFFFFFFFC)
    for i in range(0, rounded, 4):
        k1 = struct.unpack_from("<I", data, i)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    k1 = 0
    tail = length & 3
    if tail >= 3:
        k1 ^= data[rounded + 2] << 16
    if tail >= 2:
        k1 ^= data[rounded + 1] << 8
    if tail >= 1:
        k1 ^= data[rounded]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


@register
class ExposedFilesModule(Module):
    name = "exposed"
    title = "Publicly exposed paths"
    description = "robots.txt, security.txt, sitemaps, and common metadata files."
    accepts = frozenset({TargetType.DOMAIN, TargetType.URL})
    active = True

    #: Only files that are *meant* to be public, plus metadata endpoints that
    #: are routinely left readable. This is not a content-discovery brute force
    #: and deliberately does not probe for backups, dumps or admin panels.
    PATHS = (
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt",
        "/security.txt",
        "/.well-known/change-password",
        "/humans.txt",
        "/ads.txt",
        "/app-ads.txt",
        "/.well-known/openid-configuration",
        "/manifest.json",
        "/crossdomain.xml",
    )

    def run(self, target: str, result: ScanResult) -> None:
        root, base, _ = _reach(self.http, target)
        if root.status == 0:
            result.error(f"could not reach {base}: {root.error}")
            return
        checks = self.http.map(lambda p: (p, self.http.get(base + p)), self.PATHS)
        for pair in checks:
            if not pair:
                continue
            path, resp = pair
            if not resp.ok or not resp.body:
                continue
            ctype = resp.header("content-type", "")
            # A SPA that 200s every path would otherwise report all of these.
            if "html" in ctype and path.endswith((".txt", ".xml")):
                continue
            result.add(path, f"{len(resp.body)} bytes, {ctype.split(';')[0]}",
                       source="http", url=resp.url, severity=Severity.INFO)

            if path.endswith("robots.txt"):
                hidden = re.findall(r"(?im)^\s*Disallow:\s*(\S+)", resp.text)
                interesting = [p for p in dict.fromkeys(hidden) if p not in ("/", "")]
                if interesting:
                    result.add(
                        "robots.txt disallow entries",
                        interesting[:40],
                        source="robots",
                        severity=Severity.NOTABLE,
                        extra={"note": "paths the owner does not want indexed"},
                    )
                for sm in re.findall(r"(?im)^\s*Sitemap:\s*(\S+)", resp.text):
                    result.add("sitemap", sm, source="robots", url=sm)

            if "security.txt" in path:
                for contact in re.findall(r"(?im)^Contact:\s*(\S+)", resp.text):
                    result.add("security contact", contact, source="security.txt",
                               severity=Severity.NOTABLE)
                    if contact.lower().startswith("mailto:"):
                        result.entity(EntityType.EMAIL, contact[7:], relation="security-contact",
                                      evidence="published-contact",
                                      detail="address in security.txt")


@register
class WaybackModule(Module):
    name = "wayback"
    title = "Archive history"
    description = "Internet Archive first/last capture and interesting archived paths."
    accepts = frozenset({TargetType.DOMAIN, TargetType.URL})
    slow = True

    def run(self, target: str, result: ScanResult) -> None:
        host = hostname_of(target)
        url = (
            "https://web.archive.org/cdx/search/cdx"
            f"?url={urllib.parse.quote(host)}/*&output=json&fl=timestamp,original,statuscode"
            "&collapse=urlkey&limit=3000"
        )
        resp = self.http.get(url, timeout=45)
        rows = resp.json()
        if not isinstance(rows, list) or len(rows) < 2:
            result.error("Internet Archive returned no usable data (it is often rate-limited)")
            return

        header, *data = rows
        stamps = sorted(r[0] for r in data if r and r[0])
        if stamps:
            result.add("first capture", _stamp(stamps[0]), source="wayback",
                       url=f"https://web.archive.org/web/{stamps[0]}/{host}")
            result.add("last capture", _stamp(stamps[-1]), source="wayback",
                       url=f"https://web.archive.org/web/{stamps[-1]}/{host}")
        result.add("archived URLs", len(data), source="wayback")

        # Archived config-ish URLs are a classic source of stale credentials and
        # forgotten endpoints; the archive holds them long after the site drops them.
        pattern = re.compile(
            r"\.(env|sql|bak|old|log|zip|tar\.gz|json|yml|yaml|conf|ini|pem|key)(\?|$)", re.I
        )
        notable = [r[1] for r in data if len(r) > 1 and pattern.search(str(r[1]))]
        if notable:
            result.add(
                "archived files of interest",
                sorted(set(notable))[:50],
                source="wayback",
                severity=Severity.HIGH,
                confidence=Confidence.POSSIBLE,
                extra={"count": len(set(notable))},
            )

        params = set()
        for r in data:
            if len(r) > 1 and "?" in str(r[1]):
                params.update(
                    k for k, _ in urllib.parse.parse_qsl(urllib.parse.urlsplit(r[1]).query)
                )
        if params:
            result.add("historic query parameters", sorted(params)[:60], source="wayback")

        subs = {
            hostname_of(str(r[1]))
            for r in data
            if len(r) > 1 and hostname_of(str(r[1])).endswith(host)
        }
        subs.discard(host)
        if subs:
            result.add("hostnames seen in archive", sorted(subs)[:50], source="wayback")
            for s in sorted(subs)[:15]:
                result.entity(EntityType.DOMAIN, s, relation="subdomain-of",
                              evidence="subdomain-of",
                              detail="seen in the Internet Archive")


def _stamp(ts: str) -> str:
    try:
        return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"
    except Exception:
        return ts
