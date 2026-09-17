"""DNS over HTTPS.

Resolving through DoH rather than the system resolver buys three things that
matter for OSINT work: it is identical on every OS (no dnspython, no
``nslookup`` parsing), it is not coloured by the operator's local DNS or split
horizon, and it leaves no query in the local network's resolver logs.

Cloudflare is tried first, Google second. Both speak the same JSON shape.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .http import Fetcher

RESOLVERS = (
    ("cloudflare", "https://cloudflare-dns.com/dns-query?name={name}&type={rtype}"),
    ("google", "https://dns.google/resolve?name={name}&type={rtype}"),
)

#: Human labels for the DNS rcodes we actually care about.
RCODE = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}


def resolve(http: Fetcher, name: str, rtype: str = "A") -> list[str]:
    """Return the rdata strings for ``name``/``rtype``, or an empty list."""
    answers, _ = resolve_full(http, name, rtype)
    return answers


def resolve_full(http: Fetcher, name: str, rtype: str = "A") -> tuple[list[str], str]:
    """Return ``(rdata, status)`` where status is an rcode name or an error."""
    q = urllib.parse.quote(name.strip().rstrip("."))
    for _, template in RESOLVERS:
        url = template.format(name=q, rtype=rtype.upper())
        resp = http.get(url, headers={"accept": "application/dns-json"})
        data = resp.json()
        if not isinstance(data, dict):
            continue
        status = RCODE.get(data.get("Status", -1), f"RCODE{data.get('Status')}")
        wanted = _TYPE_NUM.get(rtype.upper())
        records = [a for a in data.get("Answer", []) if wanted is None or a.get("type") == wanted]
        # Fall back to every answer when the type filter is too strict
        # (CNAME chains return the CNAME record alongside the A records).
        if not records and data.get("Answer"):
            records = data["Answer"]
        return [_rdata(str(a.get("data", ""))) for a in records], status
    return [], "unreachable"


def _rdata(value: str) -> str:
    """Normalise a DoH rdata string.

    A TXT record longer than 255 bytes is transmitted as several character
    strings, and the JSON API hands them back as ``"part one" "part two"``.
    Naively stripping the outer quotes leaves the seam visible in the middle of
    an SPF record, which then fails to parse. Concatenate the chunks instead,
    which is what a resolver does.
    """
    value = value.strip()
    if value.startswith('"') and value.endswith('"') and '" "' in value:
        return "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', value))
    return value.strip('"')


def resolves(http: Fetcher, name: str) -> bool:
    answers, status = resolve_full(http, name, "A")
    if answers:
        return True
    answers6, _ = resolve_full(http, name, "AAAA")
    return bool(answers6) and status != "NXDOMAIN"


_TYPE_NUM = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "CAA": 257,
}
