"""Typed entities: the nouns an investigation is actually made of.

A :class:`~nova_osint.core.models.Finding` is a *statement* ("mail exchangers:
alt1.aspmx.l.google.com"). An :class:`Entity` is a *thing* that can be looked up
again, pivoted from, and compared across cases. The difference matters: a scan
that only produces findings can be read, but it cannot be traversed, and two
scans of the same thing cannot be compared except by string-diffing prose.

Three rules hold everything together:

* **One canonical form per entity.** ``Example.COM.``, ``example.com`` and
  ``xn--...`` must collapse to a single node or the graph grows a duplicate for
  every spelling a source happens to use. :func:`canonical` owns that, per type.
* **Canonicalisation never loses the original.** The raw spelling is evidence -
  a hostname that arrived with a trailing dot came from DNS, an email that
  arrived tagged tells you how the address was handed out. ``Entity.raw`` keeps
  it; ``Entity.value`` is what the graph keys on.
* **Confusables are a finding, not a normalisation.** ``exampIe.com`` (capital
  I) is *not* ``example.com`` and must never be folded into it. It gets its own
  node plus a ``looks-like`` edge, because the whole point is to notice it.

Everything here is stdlib-only and pure: no network, no I/O, no clock. That is
deliberate - it makes the canonicalisation table trivially testable and lets the
store, the graph and the renderers all agree on identity without a scan running.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .models import TargetType

# ---------------------------------------------------------------------------
# types
# ---------------------------------------------------------------------------


class EntityType(str, Enum):
    """What kind of thing a node is.

    Wider than :class:`TargetType` on purpose. ``TargetType`` answers "what did
    the user type?"; this answers "what did we find?", and most of what we find
    is not something a person would ever type as a starting point - an SPKI
    hash, a Google Analytics property, an ASN.
    """

    DOMAIN = "domain"          # registrable name: example.com
    HOST = "host"              # fully qualified name: www.example.com
    IP = "ip"
    CIDR = "cidr"
    ASN = "asn"
    EMAIL = "email"
    USERNAME = "username"
    PERSON = "person"
    ORG = "org"
    PHONE = "phone"
    URL = "url"
    CERT = "cert"              # certificate, keyed by sha256 fingerprint
    SPKI = "spki"              # subject public key hash - survives re-issuance
    KEY = "key"                # SSH/GPG key fingerprint
    TRACKER = "tracker"        # GA / AdSense / Pixel / Yandex property id
    FAVICON = "favicon"        # favicon hash
    FILEHASH = "filehash"
    ADDRESS = "address"        # postal
    CRYPTO = "crypto"          # wallet address
    UNKNOWN = "unknown"

    @property
    def lookupable(self) -> bool:
        """Can a module take this as a target and learn something new?

        Frontier expansion only enqueues these. An SPKI hash is a superb
        *correlator* - two hosts sharing one are related - but there is nothing
        to go and fetch about the hash itself, so enqueuing it wastes a slot.
        """
        return self in _LOOKUPABLE


_LOOKUPABLE = frozenset({
    EntityType.DOMAIN, EntityType.HOST, EntityType.IP, EntityType.CIDR,
    EntityType.ASN, EntityType.EMAIL, EntityType.USERNAME, EntityType.PHONE,
    EntityType.URL,
    # A name is searchable, but it is the weakest kind of lead there is, so the
    # relevance score has to carry it rather than the type. See PERSON_NAME_RE.
    EntityType.PERSON,
})


#: How a user-typed target maps onto a graph node. ``HOST`` vs ``DOMAIN`` is
#: decided later by :func:`split_host` - the registry cannot tell them apart and
#: does not need to.
FROM_TARGET_TYPE = {
    TargetType.DOMAIN: EntityType.DOMAIN,
    TargetType.EMAIL: EntityType.EMAIL,
    TargetType.USERNAME: EntityType.USERNAME,
    TargetType.PERSON: EntityType.PERSON,
    TargetType.IP: EntityType.IP,
    TargetType.PHONE: EntityType.PHONE,
    TargetType.URL: EntityType.URL,
    TargetType.UNKNOWN: EntityType.UNKNOWN,
}

#: The reverse, for handing an entity back to the existing module machinery.
TO_TARGET_TYPE = {
    EntityType.DOMAIN: TargetType.DOMAIN,
    EntityType.HOST: TargetType.DOMAIN,
    EntityType.EMAIL: TargetType.EMAIL,
    EntityType.USERNAME: TargetType.USERNAME,
    EntityType.PERSON: TargetType.PERSON,
    EntityType.IP: TargetType.IP,
    EntityType.PHONE: TargetType.PHONE,
    EntityType.URL: TargetType.URL,
}


# ---------------------------------------------------------------------------
# canonicalisation
# ---------------------------------------------------------------------------

_TAGGED = re.compile(r"\+[^@]*$")
_MULTI_DOT = re.compile(r"\.{2,}")

#: Mail providers where ``a.b@host`` and ``ab@host`` are the same inbox. This is
#: provider policy, not a standard - RFC 5321 says the local part is opaque and
#: case-sensitive, so folding anywhere else would be inventing an equivalence.
_DOT_FOLDING = frozenset({"gmail.com", "googlemail.com"})

#: Second-level suffixes we must not mistake for the registrable domain.
#: A full PSL would be better; it is 250 KB and needs refreshing, so this covers
#: the cases that actually show up and :func:`registrable` documents the limit.
_TWO_LABEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "co.za", "org.za", "web.za", "net.za",
    "com.br", "net.br", "org.br", "gov.br",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "com.mx", "com.ar", "com.tr", "com.sg", "com.hk", "com.tw", "com.my",
    "co.kr", "or.kr", "go.kr",
    "com.ph", "com.vn", "co.id", "com.pk", "com.ua", "com.pl", "com.ru",
    "eu.org", "github.io", "gitlab.io", "pages.dev", "workers.dev",
    "vercel.app", "netlify.app", "herokuapp.com", "azurewebsites.net",
    "s3.amazonaws.com", "cloudfront.net", "firebaseapp.com", "web.app",
})


def canonical(etype: EntityType, value: Any) -> str:
    """One spelling per thing. Returns ``""`` when the value is unusable.

    The caller decides what an empty return means; the graph refuses to create a
    node for one, which is what stops a parse failure from becoming a phantom
    entity with an empty name.
    """
    text = str(value or "").strip()
    if not text:
        return ""

    if etype in (EntityType.DOMAIN, EntityType.HOST):
        return _canon_host(text)
    if etype is EntityType.EMAIL:
        return _canon_email(text)
    if etype is EntityType.IP:
        return _canon_ip(text)
    if etype is EntityType.CIDR:
        return _canon_cidr(text)
    if etype is EntityType.ASN:
        digits = re.sub(r"\D", "", text)
        return f"AS{int(digits)}" if digits else ""
    if etype is EntityType.PHONE:
        return _canon_phone(text)
    if etype is EntityType.URL:
        from .normalizer import normalize_url

        return (normalize_url(text) or text).rstrip("/")
    if etype is EntityType.USERNAME:
        # Handles are compared case-insensitively everywhere that matters, but
        # never stripped of separators: "john.doe" and "johndoe" are different
        # accounts on every site NOVA checks. Alias generation is a *transform*
        # that emits a weak edge, not a canonicalisation that asserts identity.
        return text.lstrip("@").casefold()
    if etype in (EntityType.CERT, EntityType.SPKI, EntityType.KEY,
                 EntityType.FAVICON, EntityType.FILEHASH):
        return _canon_digest(text)
    if etype in (EntityType.PERSON, EntityType.ORG):
        return _collapse_ws(text).casefold()
    return _collapse_ws(text)


def _collapse_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _canon_host(text: str) -> str:
    host = text.strip().strip(".").casefold()
    host = _MULTI_DOT.sub(".", host)
    if "/" in host or "@" in host or " " in host:
        return ""
    if host.startswith("*."):          # wildcard SAN: the name is the parent
        host = host[2:]
    try:
        # A unicode name and its punycode form are one node. encode('idna')
        # rejects names with empty or over-long labels, which is the check we
        # want anyway - a bad name should not become a node.
        host = host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        if any(ord(c) > 127 for c in host):
            return ""
    return host if "." in host else ""


def _canon_email(text: str) -> str:
    text = text.strip().strip("<>").casefold()
    if text.count("@") != 1:
        return ""
    local, _, domain = text.partition("@")
    domain = _canon_host(domain)
    if not local or not domain:
        return ""
    return f"{local}@{domain}"


def _canon_ip(text: str) -> str:
    try:
        # str() on the parsed object compresses IPv6 and strips leading zeros,
        # so 2001:0db8::0001 and 2001:db8::1 stop being two different nodes.
        return str(ipaddress.ip_address(text.strip().strip("[]")))
    except ValueError:
        return ""


_HEX_DIGEST = re.compile(r"^[0-9A-Fa-f]{8,128}$")


def _canon_digest(text: str) -> str:
    """Canonicalise a fingerprint without destroying it.

    Two shapes turn up and they need opposite treatment. A hex digest is
    case-insensitive and often colon-separated (``AA:BB:CC``), so it folds to
    lowercase with the separators removed. An OpenSSH or SPKI fingerprint is
    **base64**, where case is significant - ``SHA256:abc`` and ``SHA256:ABC`` are
    different keys - so casefolding it can merge two unrelated identities into
    one node, which is the worst error this whole module can make.

    A value may also be prefixed (``ssh/SHA256:...``, ``dom/<sha256>``); the
    prefix is kept, because it is what stops a favicon hash and a file hash that
    happen to collide from becoming the same entity.
    """
    text = re.sub(r"\s+", "", text)
    prefix, sep, body = text.rpartition("/")
    head = prefix + sep

    # Plain hex, with or without colon separators: AA:BB:CC and aabbcc are one
    # fingerprint. Must be tried first, or the leading "AA" is mistaken for an
    # algorithm label.
    stripped = body.replace(":", "")
    if _HEX_DIGEST.match(stripped):
        return f"{head}{stripped.lower()}"

    # Labelled hex: sha1:AABBCC. Only the digest folds; the label stays as the
    # emitter wrote it, so the value still matches what the tool it came from
    # prints and a user can grep one against the other.
    algo, algo_sep, digest = body.partition(":")
    if algo_sep and algo.isalnum() and _HEX_DIGEST.match(digest.replace(":", "")):
        return f"{head}{algo}:{digest.replace(':', '').lower()}"

    # Anything else - base64 and friends - is returned untouched.
    return f"{head}{body}"


def _canon_cidr(text: str) -> str:
    try:
        return str(ipaddress.ip_network(text.strip(), strict=False))
    except ValueError:
        return ""


def _canon_phone(text: str) -> str:
    """Best-effort E.164. Digits only, ``+`` kept when the source implied it.

    Deliberately dumber than ``phonenumbers``: that library is optional and this
    has to work without it. A number that arrives without a country code stays
    national, because guessing a region is exactly the kind of invention the
    normalizer's rule forbids.
    """
    text = text.strip()
    plus = text.startswith("+") or text.startswith("00")
    if plus:
        # "+44 (0)20 ..." - the bracketed 0 is a national trunk prefix that is
        # dropped when dialling internationally. Keeping it produces a number
        # one digit too long that matches nothing.
        text = re.sub(r"\(\s*0\s*\)", "", text)
    digits = re.sub(r"\D", "", text)
    if text.startswith("00"):
        digits = digits[2:]
    if not 7 <= len(digits) <= 15:
        return ""
    return f"+{digits}" if plus else digits


def split_host(host: str) -> tuple[str, str | None]:
    """``(registrable domain, subdomain or None)``.

    Used to decide whether a name is a ``DOMAIN`` node or a ``HOST`` hanging off
    one, so ``mail.example.com`` and ``example.com`` are two nodes with an edge
    rather than two unrelated strings.
    """
    name = _canon_host(host)
    if not name:
        return "", None
    labels = name.split(".")
    depth = 3 if ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES and len(labels) >= 3 else 2
    if len(labels) <= depth:
        return name, None
    return ".".join(labels[-depth:]), ".".join(labels[:-depth])


def registrable(host: str) -> str:
    """The domain someone actually registered.

    Limit worth knowing: the suffix list above is hand-picked, not the full
    Public Suffix List. An exotic multi-label ccTLD will be split one label too
    shallow. That produces a slightly wrong parent edge, never a wrong fact.
    """
    return split_host(host)[0]


# ---------------------------------------------------------------------------
# confusables
# ---------------------------------------------------------------------------

#: Characters that render close enough to an ASCII letter to fool a reader.
#: Keyed by the confusable, valued by what it imitates. Covers the Cyrillic and
#: Greek overlap plus the classic ASCII-on-ASCII tricks (rn/m, l/1/I, 0/O).
_CONFUSABLE = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "и": "u", "к": "k", "м": "m",
    "н": "h", "т": "t", "в": "b", "З": "3", "һ": "h",
    "α": "a", "ο": "o", "ρ": "p", "υ": "u", "ι": "i",
    "κ": "k", "ν": "v", "χ": "x", "γ": "y", "ε": "e",
    "ı": "i", "ł": "l", "ø": "o", "ç": "c", "ñ": "n",
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
}


def skeleton(text: str) -> str:
    """Fold a string to its visual shape, for typosquat detection only.

    Never use this for identity. ``paypa1.com`` and ``paypal.com`` share a
    skeleton precisely because one is pretending to be the other; collapsing
    them into one node would delete the finding.
    """
    folded = unicodedata.normalize("NFKD", text.casefold())
    folded = "".join(c for c in folded if not unicodedata.combining(c))
    out = "".join(_CONFUSABLE.get(c, c) for c in folded)
    # rn -> m is the one multi-character substitution worth making; it is the
    # most-used homoglyph on the ASCII-only web (rnicrosoft.com).
    return out.replace("rn", "m").replace("vv", "w")


def looks_like(a: str, b: str) -> bool:
    """True when two names are visually confusable but not equal."""
    return a != b and skeleton(a) == skeleton(b)


def edit_distance(a: str, b: str, *, cap: int = 4) -> int:
    """Levenshtein, bailing out once it exceeds ``cap``.

    The cap is not an optimisation detail - it is the point. Callers only ever
    ask "is this within N edits", and an uncapped distance over a 4000-entry
    candidate list is the kind of quadratic surprise that makes a scan hang.
    """
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


# ---------------------------------------------------------------------------
# the entity
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Entity:
    """A node. Immutable, because its identity *is* its value.

    Mutable state about an entity (score, when we saw it, whether it has been
    expanded) lives on the graph, not here. That split is what lets the same
    entity be shared between two cases without one case's scoring leaking into
    the other's.
    """

    etype: EntityType
    value: str
    raw: str = ""
    #: Free-form context from whoever created it: registrar, port, label.
    attrs: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    @property
    def eid(self) -> str:
        """Stable id, safe in a URL, a filename and a SQLite key."""
        return f"{self.etype.value}:{self.value}"

    @property
    def display(self) -> str:
        return self.raw or self.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "eid": self.eid,
            "type": self.etype.value,
            "value": self.value,
            "raw": self.raw,
            "attrs": self.attrs,
        }

    @classmethod
    def make(cls, etype: EntityType, value: Any, **attrs: Any) -> Entity | None:
        """Build an entity, or ``None`` if the value will not canonicalise.

        Returning ``None`` rather than raising is deliberate: modules call this
        on scraped text dozens of times per run, and a parse miss is normal
        operation, not an error worth unwinding a scan for.
        """
        raw = str(value or "").strip()
        canon = canonical(etype, raw)
        if not canon:
            return None
        # A name with a subdomain is a HOST even when the caller said DOMAIN;
        # getting this wrong is what makes example.com and www.example.com fail
        # to connect.
        if etype is EntityType.DOMAIN and split_host(canon)[1]:
            etype = EntityType.HOST
        # Keep the original spelling whenever it differs at all, not only when
        # it differs by more than case. Case is meaningless in DNS and very
        # meaningful in a person's name: dropping it rendered every candidate in
        # a dossier as "matthew prince (q51665553)", which is the right node and
        # the wrong thing to put in a document somebody will read.
        return cls(etype, canon, raw if raw != canon else "", dict(attrs))

    def fingerprint(self) -> str:
        """Short content hash - used for evidence filenames and diff keys."""
        return hashlib.sha256(self.eid.encode()).hexdigest()[:16]
