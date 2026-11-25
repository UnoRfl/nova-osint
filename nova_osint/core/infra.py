"""Telling a target's own infrastructure apart from the internet's plumbing.

The single largest source of wasted budget and false connection in a domain
investigation is co-location. A site on Vercel, Cloudflare Pages, Netlify,
Shopify or an AWS load balancer answers on an address shared with tens of
thousands of unrelated sites. Ask passive DNS what else lives there and you
get forty names; follow them and the graph is no longer about your target.

A real scan did exactly that: `www.designsbyracquel.com` resolved to a Vercel
anycast address, and the run spent five minutes and forty-five pivots on
`cigar.cafe`, `ournews.school` and `2026.fragile.ventures` - none of which
have anything to do with a jeweller in Singapore.

How the decision is made
------------------------

Three signals, strongest first, and the strongest one needs no list at all:

1. **Population.** If passive DNS knows many unrelated names on one address,
   it is shared. This is measured, not remembered, so it works for a host
   nobody has heard of. It is the same reasoning the graph already uses when
   it demotes an edge by the degree of its busier endpoint - applied earlier,
   before the pivots are created rather than after.
2. **Naming.** Providers label their own edges: `no-sni.vercel-infra.com`,
   `*.cloudfront.net`, `*.1e100.net`. A PTR or certificate CN in provider
   space says the address belongs to the provider, not the target.
3. **Ownership.** A handful of AS owners are cloud and CDN operators whose
   address space is by definition not a target's own.

Prior art, deliberately followed: OWASP Amass declines to expand into cloud
netblocks rather than trying to filter the results afterwards, and SpiderFoot
records co-hosted sites as *affiliates* - a separate, weaker class - with a
cap on how many one address may contribute. Both treat co-location as a lead
requiring corroboration. Neither treats it as a link, and neither did NOVA in
its documentation; it just did it anyway in code.

What this module does **not** do is hide the finding. A shared address is
still reported, with its population and the reason it was judged shared,
because "this site is on Vercel with forty thousand others" is a real and
occasionally useful fact. What changes is that it stops generating pivots.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["SharedVerdict", "judge_host", "COHOST_SUSPICIOUS", "COHOST_CERTAIN"]

#: Above this many co-located names, treat an address as shared unless
#: something says otherwise. Small organisations do host a handful of their
#: own sites together, and that is a genuine link worth following.
COHOST_SUSPICIOUS = 8
#: Above this, no judgement call is needed.
COHOST_CERTAIN = 20

#: Names providers give their own edge infrastructure. Matched against a PTR
#: record or a certificate common name, never against the target's own name.
_PROVIDER_NAMES = re.compile(
    r"(?:^|\.)(?:"
    r"vercel-infra\.com|vercel-dns[0-9-]*\.com|vercel\.app|"
    r"cloudflare(?:ssl)?\.(?:com|net)|cdn\.cloudflare\.net|"
    r"cloudfront\.net|amazonaws\.com|elb\.amazonaws\.com|"
    r"fastly(?:lb)?\.net|akamai(?:edge|technologies|hd)?\.net|akamaized\.net|"
    r"1e100\.net|googleusercontent\.com|googlehosted\.com|"
    r"azureedge\.net|azurewebsites\.net|trafficmanager\.net|"
    r"netlify\.(?:app|com)|herokuapp\.com|herokudns\.com|"
    r"shopify(?:cloud|cdn)?\.com|myshopify\.com|squarespace\.com|"
    r"wpengine\.com|wixdns\.net|github\.io|gitlab\.io|pages\.dev|workers\.dev|"
    r"digitaloceanspaces\.com|linodeusercontent\.com|hetzner\.(?:com|cloud)|"
    r"ovh\.net|contabo\.net|bunnycdn\.com|b-cdn\.net|stackpathdns\.com|"
    r"incapdns\.net|sucuri\.net|imperva\.com"
    r")$", re.I)

#: AS owners whose address space is shared hosting or CDN by definition.
_PROVIDER_ORGS = (
    "cloudflare", "amazon", "aws", "google", "microsoft", "azure", "fastly",
    "akamai", "vercel", "netlify", "heroku", "digitalocean", "linode",
    "hetzner", "ovh", "contabo", "leaseweb", "godaddy", "namecheap",
    "squarespace", "wix", "shopify", "automattic", "wordpress", "gcore",
    "bunny", "stackpath", "incapsula", "imperva", "sucuri", "oracle",
    "alibaba", "tencent", "cloudflarenet", "unified layer", "hostgator",
    "bluehost", "dreamhost", "siteground", "ionos", "1&1", "strato",
)


@dataclass(frozen=True)
class SharedVerdict:
    """Whether an address is shared, on what basis, and how sure."""

    shared: bool
    reason: str = ""
    #: "population" | "naming" | "ownership" | "" - which signal decided it.
    basis: str = ""
    cohosted: int = 0

    def __bool__(self) -> bool:
        return self.shared

    @property
    def certain(self) -> bool:
        return self.shared and (self.basis in ("naming", "ownership")
                                or self.cohosted >= COHOST_CERTAIN)


def judge_host(*, cohosted: int = 0, as_owner: str = "", ptr: str = "",
               cert_cn: str = "") -> SharedVerdict:
    """Is this address shared infrastructure rather than the target's own?

    Takes the signals rather than fetching them, so it is pure, testable
    without a socket, and usable from a module, from the graph or from a
    stored case during replay.
    """
    for name in (ptr, cert_cn):
        host = str(name or "").strip().strip(".").casefold()
        if host and _PROVIDER_NAMES.search(host):
            return SharedVerdict(True, f"{host} is provider infrastructure",
                                 "naming", cohosted)

    owner = str(as_owner or "").casefold()
    if owner:
        for org in _PROVIDER_ORGS:
            if org in owner:
                return SharedVerdict(
                    True, f"announced by {as_owner.strip()}, a cloud or CDN "
                          f"operator", "ownership", cohosted)

    if cohosted >= COHOST_CERTAIN:
        return SharedVerdict(True, f"{cohosted} unrelated names resolve here",
                             "population", cohosted)
    if cohosted >= COHOST_SUSPICIOUS:
        return SharedVerdict(True, f"{cohosted} other names resolve here, which "
                                   f"is more than one owner usually has",
                             "population", cohosted)
    return SharedVerdict(False, "", "", cohosted)


#: How many co-located names are worth naming in a report when the address is
#: shared. The full list is a directory of strangers; a sample plus the count
#: is what an investigator can actually use.
SAMPLE = 10


#: Edge ranges where one address fronts thousands of unrelated sites, so an
#: address inside them identifies the *provider*, never the target. Static,
#: because the pivot gate must decide before any lookup is spent.
#: Cloudflare: https://www.cloudflare.com/ips-v4 and /ips-v6 (fetched
#: 2026-11-26). Vercel: blocks confirmed by RDAP (VERCEL-01/08/09).
#: Anything not listed is still caught at lookup time by ``judge_host``
#: on the announcing AS.
_EDGE_RANGES: dict[str, tuple[str, ...]] = {
    "Cloudflare": (
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
        "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    ),
    "Vercel": ("76.76.21.0/24", "216.150.1.0/24", "216.150.16.0/24"),
}


def _compile_edges():  # type: ignore[no-untyped-def]
    import ipaddress

    return [(owner, ipaddress.ip_network(cidr))
            for owner, cidrs in _EDGE_RANGES.items() for cidr in cidrs]


_EDGE_NETS = _compile_edges()


def shared_edge(address: str) -> str:
    """The CDN whose shared edge this address is, or ``""``."""
    import ipaddress

    try:
        ip = ipaddress.ip_address(str(address).strip())
    except ValueError:
        return ""
    for owner, net in _EDGE_NETS:
        if ip.version == net.version and ip in net:
            return owner
    return ""
