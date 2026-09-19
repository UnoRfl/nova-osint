"""What a page says about its owner, in the page's own machine-readable words.

Every commercial site on the internet publishes a block of JSON describing who
runs it, what they do, where they are and which social accounts are theirs -
because Google asks for it. It is called schema.org, it sits in a
``<script type="application/ld+json">`` tag, and NOVA was not reading it.

That omission was expensive in two places at once:

**Social accounts.** ``schema.org`` has a property called ``sameAs`` whose
entire purpose is "these other profiles are also me". A jeweller's site lists
its Facebook page, its Instagram, its Pinterest and its X account there, signed
by nobody but published deliberately by the owner. Meanwhile NOVA was marking
Facebook, Instagram and Threads *unreachable* - true of a username check,
irrelevant when the subject has already told you the URL. The platforms that
refuse anonymous lookups are exactly the platforms businesses advertise, so the
one source that works is the one nobody has to break into.

**Occupation.** ``jobTitle``, ``worksFor``, ``founder``, ``employee`` and
``LocalBusiness`` answer "what does this person do" and "do they own a company"
directly, in a typed field, on a page anyone may read. The dossier already had
somewhere to put an employer and a role - :mod:`~nova_osint.core.target_dossier`
consolidates them carefully and declines to pair a title with a company it
cannot justify - and almost nothing was ever feeding it.

What this file is, and is not
-----------------------------

A **parser**. Pure, stdlib, no socket, no clock. It takes HTML and a base URL
and returns what the page claimed. Deciding what a claim is *worth* is the
graph's job, and deciding whether the page is even about the subject is the
caller's.

That last point is the one worth holding on to. A page saying "our founder is
Jane Doe" is excellent evidence about the site and no evidence at all about
a Jane Doe found somewhere else. Everything here is therefore reported as
**declared by a page**, with that page's URL attached, and never as a fact about
a person.

Three formats, because sites use all three
------------------------------------------

*JSON-LD* is the modern one and by far the richest; it may be a single object,
a list, or a ``@graph`` of cross-referenced nodes. *Open Graph* meta tags are
nearly universal and carry the site's own name and description. *Microdata*
(``itemprop`` attributes) is older and still common on hand-built pages, which
is to say on exactly the small-business sites where the other two are missing.

Also read: ``rel="me"``. It predates schema.org, it is the convention IndieAuth
is built on, and it means the same thing - a link the page's author asserts is
another of their own identities.
"""

from __future__ import annotations

import html.parser
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

__all__ = ["Declared", "SiteIdentity", "harvest", "PLATFORM_OF", "platform_of"]


# ---------------------------------------------------------------------------
# what a social URL belongs to
# ---------------------------------------------------------------------------

#: Host fragment to platform name, for the platforms a person actually links.
#: Kept here rather than imported from :mod:`~nova_osint.core.socials` so the
#: parser stays free of the rest of the package; the two tables overlap on
#: purpose and a test asserts this one is a subset.
PLATFORM_OF: dict[str, str] = {
    "facebook.com": "Facebook",
    "fb.com": "Facebook",
    "fb.me": "Facebook",
    "messenger.com": "Facebook",
    "instagram.com": "Instagram",
    "threads.net": "Threads",
    "threads.com": "Threads",
    "twitter.com": "X / Twitter",
    "x.com": "X / Twitter",
    "linkedin.com": "LinkedIn",
    "tiktok.com": "TikTok",
    "youtube.com": "YouTube",
    "pinterest.com": "Pinterest",
    "snapchat.com": "Snapchat",
    "reddit.com": "Reddit",
    "t.me": "Telegram",
    "wa.me": "WhatsApp",
    "bsky.app": "Bluesky",
    "github.com": "GitHub",
    "gitlab.com": "GitLab",
    "medium.com": "Medium",
    "substack.com": "Substack",
    "behance.net": "Behance",
    "dribbble.com": "Dribbble",
    "etsy.com": "Etsy",
    "yelp.com": "Yelp",
    "tripadvisor.com": "TripAdvisor",
    "vimeo.com": "Vimeo",
    "twitch.tv": "Twitch",
    "soundcloud.com": "SoundCloud",
    "spotify.com": "Spotify",
    "patreon.com": "Patreon",
    "mastodon.social": "Mastodon",
    "vk.com": "VK",
    "weibo.com": "Weibo",
    "wechat.com": "WeChat",
    "xing.com": "XING",
}


def platform_of(url: str) -> str:
    """The platform a URL belongs to, or ``""``."""
    try:
        host = (urllib.parse.urlsplit(url).hostname or "").casefold()
    except ValueError:
        return ""
    host = host[4:] if host.startswith("www.") else host
    for fragment, name in PLATFORM_OF.items():
        if host == fragment or host.endswith("." + fragment):
            return name
    return ""


# ---------------------------------------------------------------------------
# records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Declared:
    """One claim a page made, and where on the page it made it.

    ``where`` is the format - ``json-ld``, ``opengraph``, ``microdata``,
    ``rel-me`` - because they are not equally reliable. A ``sameAs`` inside a
    ``Person`` node is a deliberate, structured assertion; an Open Graph title
    is whatever the CMS put there. The report shows which, and the caller
    weights accordingly.
    """

    value: str
    where: str
    #: schema.org type the claim hung off, when there was one: ``Person``,
    #: ``Organization``, ``LocalBusiness``…
    subject_type: str = ""
    #: The name of the thing the claim was about, when the page gave one.
    subject: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"value": self.value, "where": self.where,
                "subject_type": self.subject_type, "subject": self.subject,
                "detail": self.detail}


@dataclass
class SiteIdentity:
    """Everything one page declared about whoever runs it."""

    url: str = ""
    #: Social and other profile URLs the page asserts are the same entity.
    accounts: list[Declared] = field(default_factory=list)
    people: list[Declared] = field(default_factory=list)
    organisations: list[Declared] = field(default_factory=list)
    #: ``jobTitle`` and the like.
    roles: list[Declared] = field(default_factory=list)
    #: ``worksFor``: a person and the organisation they work for.
    employers: list[Declared] = field(default_factory=list)
    #: ``founder`` / ``owner``: the strongest occupational claim there is,
    #: because it says the subject *is* the business rather than works at one.
    owners: list[Declared] = field(default_factory=list)
    emails: list[Declared] = field(default_factory=list)
    phones: list[Declared] = field(default_factory=list)
    addresses: list[Declared] = field(default_factory=list)
    #: ``LocalBusiness``, ``Store``, ``Restaurant``… - the page says a real
    #: business trades here, which is a different claim from "a company exists".
    business_types: list[str] = field(default_factory=list)
    #: Formats actually present, so "no accounts found" can be told apart from
    #: "this page publishes nothing machine-readable".
    formats: set[str] = field(default_factory=set)

    def __bool__(self) -> bool:
        return bool(self.accounts or self.people or self.organisations
                    or self.roles or self.employers or self.owners
                    or self.emails or self.phones or self.addresses)

    @property
    def platforms(self) -> dict[str, list[Declared]]:
        """Declared accounts grouped by platform, several per platform allowed.

        A business commonly lists two Facebook URLs - the page and the profile -
        and a person commonly has a personal and a professional account on the
        same platform. Collapsing them to one row per platform, which is what
        the accounts panel did, throws away the second one and with it the
        reason the operator asked for this.
        """
        out: dict[str, list[Declared]] = {}
        for claim in self.accounts:
            name = platform_of(claim.value) or "Other"
            bucket = out.setdefault(name, [])
            if not any(c.value == claim.value for c in bucket):
                bucket.append(claim)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "formats": sorted(self.formats),
            "accounts": [c.to_dict() for c in self.accounts],
            "people": [c.to_dict() for c in self.people],
            "organisations": [c.to_dict() for c in self.organisations],
            "roles": [c.to_dict() for c in self.roles],
            "employers": [c.to_dict() for c in self.employers],
            "owners": [c.to_dict() for c in self.owners],
            "emails": [c.to_dict() for c in self.emails],
            "phones": [c.to_dict() for c in self.phones],
            "addresses": [c.to_dict() for c in self.addresses],
            "business_types": self.business_types,
        }


# ---------------------------------------------------------------------------
# the HTML pass
# ---------------------------------------------------------------------------

#: schema.org types that describe a trading business rather than any legal
#: entity. ``Organization`` covers a charity, a band and a government
#: department; these say somebody sells something from somewhere.
BUSINESS_TYPES = frozenset({
    "localbusiness", "store", "restaurant", "cafe", "bakery", "bar",
    "professionalservice", "homeandconstructionbusiness", "medicalbusiness",
    "financialservice", "foodestablishment", "healthandbeautybusiness",
    "legalservice", "lodgingbusiness", "automotivebusiness", "jewelrystore",
    "clothingstore", "shoppingcenter", "realestateagent", "travelagency",
    "entertainmentbusiness", "sportsactivitylocation", "selfstorage",
    "emergencyservice", "employmentagency", "insuranceagency", "dentist",
    "physician", "hospital", "childcare", "internetcafe", "library",
})

PERSON_TYPES = frozenset({"person"})
ORG_TYPES = frozenset({"organization", "corporation", "ngo", "educationalorganization",
                       "governmentorganization", "performinggroup", "newsmediaorganization",
                       "sportsorganization", "airline", "consortium", "project",
                       "fundingscheme", "librarysystem", "medicalorganization"}) | BUSINESS_TYPES


class _Scraper(html.parser.HTMLParser):
    """Collects the three formats in one pass over the document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.jsonld: list[str] = []
        self.meta: dict[str, str] = {}
        self.rel_me: list[str] = []
        self.links: list[str] = []
        self.microdata: list[tuple[str, str]] = []
        self._in_ld = False
        #: Depth-tracked so ``itemprop`` text can be picked up from the element
        #: that has no ``content`` attribute, which is the common hand-written
        #: case: ``<span itemprop="jobTitle">Goldsmith</span>``.
        self._pending_prop = ""
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script" and "json" in a.get("type", "").lower():
            self._in_ld = True
            self._text = []
            return
        if tag == "meta":
            key = (a.get("property") or a.get("name") or "").strip().lower()
            value = a.get("content", "").strip()
            if key and value:
                self.meta.setdefault(key, value)
        if tag in ("link", "a"):
            rels = a.get("rel", "").lower().split()
            href = a.get("href", "").strip()
            if "me" in rels and href:
                self.rel_me.append(href)
            elif href:
                self.links.append(href)
        if prop := a.get("itemprop", "").strip():
            inline = (a.get("content") or a.get("href") or a.get("src") or "").strip()
            if inline:
                self.microdata.append((prop.lower(), inline))
            else:
                self._pending_prop = prop.lower()
                self._text = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._in_ld:
            self._in_ld = False
            blob = "".join(self._text).strip()
            if blob:
                self.jsonld.append(blob)
            self._text = []
            return
        if self._pending_prop:
            text = " ".join("".join(self._text).split())[:200]
            if text:
                self.microdata.append((self._pending_prop, text))
            self._pending_prop = ""
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._in_ld or self._pending_prop:
            self._text.append(data)


# ---------------------------------------------------------------------------
# JSON-LD walking
# ---------------------------------------------------------------------------

_MAX_NODES = 400


def _types_of(node: dict[str, Any]) -> list[str]:
    raw = node.get("@type") or node.get("type") or ""
    values = raw if isinstance(raw, list) else [raw]
    return [str(v).rsplit("/", 1)[-1].casefold() for v in values if v]


def _name_of(node: Any) -> str:
    """A schema.org value is a string, an object with a name, or a list of both."""
    if isinstance(node, str):
        return node.strip()
    if isinstance(node, dict):
        for key in ("name", "legalName", "alternateName", "@id"):
            value = node.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _flatten(node: Any, out: list[dict[str, Any]], seen: int = 0) -> None:
    """Every object in the document, however it was nested.

    JSON-LD is allowed to be a bare object, a list, a ``@graph``, or any of
    those nested inside each other to arbitrary depth, and real sites use all
    of it. Walking the whole tree rather than reading the top level is the
    difference between finding a ``Person`` and finding the ``WebSite`` node it
    was buried under.
    """
    if len(out) >= _MAX_NODES or seen > 24:
        return
    if isinstance(node, list):
        for item in node:
            _flatten(item, out, seen + 1)
        return
    if not isinstance(node, dict):
        return
    out.append(node)
    for value in node.values():
        if isinstance(value, (list, dict)):
            _flatten(value, out, seen + 1)


_EMAIL_PREFIX = re.compile(r"^mailto:", re.I)
_TEL_PREFIX = re.compile(r"^tel:", re.I)


def _clean_contact(value: str) -> str:
    value = _EMAIL_PREFIX.sub("", _TEL_PREFIX.sub("", value.strip()))
    return " ".join(value.split())


def _address_of(node: Any) -> str:
    if isinstance(node, str):
        return " ".join(node.split())[:200]
    if not isinstance(node, dict):
        return ""
    parts = [str(node.get(k, "")).strip() for k in (
        "streetAddress", "addressLocality", "addressRegion",
        "postalCode", "addressCountry")]
    if isinstance(node.get("addressCountry"), dict):
        parts[-1] = _name_of(node["addressCountry"])
    return ", ".join(p for p in parts if p)[:200]


# ---------------------------------------------------------------------------
# the entry point
# ---------------------------------------------------------------------------


def harvest(body: str, url: str = "") -> SiteIdentity:
    """Read one page's declarations. Never raises on malformed input.

    A page with broken JSON in one ``ld+json`` block and good JSON in another
    must still yield the good one: sites routinely ship three of these blocks
    from three different plugins and one of them is always wrong.
    """
    out = SiteIdentity(url=url)
    if not body:
        return out

    scraper = _Scraper()
    try:
        scraper.feed(body)
        scraper.close()
    except Exception:                                  # noqa: BLE001 - malformed HTML
        pass

    _read_jsonld(scraper.jsonld, out)
    _read_opengraph(scraper.meta, out, url)
    _read_microdata(scraper.microdata, out)
    _read_rel_me(scraper.rel_me, out, url)
    _read_links(scraper.links, out, url)
    _dedupe(out)
    return out


def _add(bucket: list[Declared], claim: Declared) -> None:
    if claim.value and not any(c.value == claim.value and c.where == claim.where
                               for c in bucket):
        bucket.append(claim)


def _read_jsonld(blobs: list[str], out: SiteIdentity) -> None:
    nodes: list[dict[str, Any]] = []
    for blob in blobs:
        try:
            _flatten(json.loads(blob), nodes)
        except (ValueError, RecursionError):
            continue
    if nodes:
        out.formats.add("json-ld")

    for node in nodes:
        types = _types_of(node)
        is_person = any(t in PERSON_TYPES for t in types)
        is_org = any(t in ORG_TYPES for t in types)
        if not (is_person or is_org):
            # A node with no usable type can still carry sameAs - WebSite and
            # WebPage nodes often do - so it is read for accounts and skipped
            # for everything else.
            _same_as(node, out, "", "")
            continue

        name = _name_of(node)
        kind = "Person" if is_person else next(
            (t for t in types if t in BUSINESS_TYPES), "Organization")
        subject_type = "Person" if is_person else kind.title()

        if is_person and name:
            _add(out.people, Declared(name, "json-ld", "Person", name))
        if is_org and name:
            _add(out.organisations, Declared(name, "json-ld", subject_type, name))
        for t in types:
            if t in BUSINESS_TYPES and t not in out.business_types:
                out.business_types.append(t)

        _same_as(node, out, subject_type, name)

        for role in _listed(node.get("jobTitle")) + _listed(node.get("hasOccupation")):
            if text := _name_of(role):
                _add(out.roles, Declared(text, "json-ld", subject_type, name))
        for employer in _listed(node.get("worksFor")) + _listed(node.get("affiliation")):
            if text := _name_of(employer):
                _add(out.employers, Declared(text, "json-ld", subject_type, name,
                                             detail="worksFor"))
        # Both directions: a Person node naming their company, and an
        # Organization node naming its founder. The second is how a small
        # business site usually says it, and it is the one that answers
        # "does this person own a business".
        for key, detail in (("founder", "founder"), ("founders", "founder"),
                            ("owner", "owner"), ("employee", "employee"),
                            ("employees", "employee")):
            for who in _listed(node.get(key)):
                if text := _name_of(who):
                    _add(out.owners, Declared(
                        text, "json-ld", subject_type, name,
                        detail=f"{detail} of {name}" if name else detail))
                    if detail in ("founder", "owner"):
                        _add(out.people, Declared(text, "json-ld", "Person", text))

        for email in _listed(node.get("email")):
            if text := _clean_contact(_name_of(email)):
                _add(out.emails, Declared(text, "json-ld", subject_type, name))
        for phone in _listed(node.get("telephone")):
            if text := _clean_contact(_name_of(phone)):
                _add(out.phones, Declared(text, "json-ld", subject_type, name))
        for where in _listed(node.get("address")) + _listed(node.get("location")):
            if text := _address_of(where):
                _add(out.addresses, Declared(text, "json-ld", subject_type, name))


def _listed(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def _same_as(node: dict[str, Any], out: SiteIdentity, subject_type: str,
             name: str) -> None:
    """``sameAs`` is the page saying "these accounts are also me"."""
    for link in _listed(node.get("sameAs")) + _listed(node.get("url")):
        value = link if isinstance(link, str) else _name_of(link)
        value = value.strip()
        if not value.lower().startswith(("http://", "https://")):
            continue
        if not platform_of(value):
            continue
        _add(out.accounts, Declared(value, "json-ld", subject_type, name,
                                    detail="sameAs"))


_OG_ACCOUNT_KEYS = ("og:see_also", "article:author", "twitter:site",
                    "twitter:creator", "al:android:url", "al:ios:url")


def _read_opengraph(meta: dict[str, str], out: SiteIdentity, url: str) -> None:
    if not meta:
        return
    if any(k.startswith(("og:", "twitter:")) for k in meta):
        out.formats.add("opengraph")

    for key in _OG_ACCOUNT_KEYS:
        value = meta.get(key, "")
        if not value:
            continue
        if value.startswith("@") and key.startswith("twitter:"):
            value = f"https://x.com/{value[1:]}"
        if value.lower().startswith(("http://", "https://")) and platform_of(value):
            _add(out.accounts, Declared(value, "opengraph", detail=key))

    if name := meta.get("og:site_name", "").strip():
        _add(out.organisations, Declared(name, "opengraph", detail="og:site_name"))
    # ``profile:*`` is Open Graph's person vocabulary and is what a personal
    # page on a platform emits.
    first = meta.get("profile:first_name", "").strip()
    last = meta.get("profile:last_name", "").strip()
    if first or last:
        _add(out.people, Declared(" ".join(p for p in (first, last) if p),
                                  "opengraph", "Person", detail="profile:*"))


_MICRO_MAP = {
    "jobtitle": "roles",
    "worksfor": "employers",
    "founder": "owners",
    "owner": "owners",
    "email": "emails",
    "telephone": "phones",
    "sameas": "accounts",
}


def _read_microdata(pairs: list[tuple[str, str]], out: SiteIdentity) -> None:
    if not pairs:
        return
    out.formats.add("microdata")
    for prop, value in pairs:
        bucket = _MICRO_MAP.get(prop)
        if bucket is None:
            continue
        text = _clean_contact(value) if bucket in ("emails", "phones") else value.strip()
        if bucket == "accounts" and not platform_of(text):
            continue
        _add(getattr(out, bucket), Declared(text[:200], "microdata", detail=prop))


def _read_rel_me(links: list[str], out: SiteIdentity, url: str) -> None:
    """``rel="me"`` predates schema.org and means exactly the same thing."""
    if not links:
        return
    out.formats.add("rel-me")
    for href in links:
        absolute = urllib.parse.urljoin(url, href) if url else href
        if platform_of(absolute):
            _add(out.accounts, Declared(absolute, "rel-me", detail='rel="me"'))


#: ``wa.me/6580562021`` and ``t.me/name`` put the identifier in the path, and a
#: click-to-chat link is the commonest way a small business publishes a mobile
#: number without writing it down as text.
_CHAT_NUMBER = re.compile(r"^(?:wa\.me|api\.whatsapp\.com)$", re.I)


def _read_links(links: list[str], out: SiteIdentity, url: str) -> None:
    """Plain links to social platforms, which is how most sites actually do it.

    Measured before writing this: the live site this feature was built for
    publishes **no** JSON-LD, no microdata and one social link - a click-to-chat
    URL in the footer. Harvesting only the structured formats would have found
    a site name and nothing else, and reported that as "no accounts".

    A footer icon is genuinely weaker evidence than ``sameAs``: it is a link,
    and a link can point at a supplier, a designer's portfolio or a friend. So
    it is collected, marked ``link``, and ranked below every declared format -
    a lead to check, not an assertion to publish.
    """
    if not links:
        return
    seen_platform = False
    for href in links:
        absolute = urllib.parse.urljoin(url, href) if url else href
        if not absolute.lower().startswith(("http://", "https://")):
            continue
        try:
            parts = urllib.parse.urlsplit(absolute)
        except ValueError:
            continue
        host = (parts.hostname or "").casefold()
        if _CHAT_NUMBER.match(host) or host == "www.wa.me":
            # Path only. The query on these links is a prefilled message, and
            # its percent-escapes are digits: ``?text=Hello%2C%20I'm`` turned
            # +6580562021 into +658056202122020 the first time this ran.
            digits = re.sub(r"\D", "", parts.path)[:15]
            if 8 <= len(digits) <= 15:
                _add(out.phones, Declared(f"+{digits}", "link",
                                          detail="WhatsApp click-to-chat link"))
        if platform_of(absolute):
            seen_platform = True
            # Query strings on a share link carry the *referring* page, not an
            # account: facebook.com/sharer?u=… is this site, not a profile.
            if parts.path.strip("/") in ("", "sharer", "sharer.php", "share",
                                         "intent/tweet", "shareArticle"):
                continue
            _add(out.accounts, Declared(absolute, "link", detail="linked from the page"))
    if seen_platform:
        out.formats.add("link")


def _dedupe(out: SiteIdentity) -> None:
    """One URL declared three ways is one declaration, by the best format.

    Ordering matters: a ``sameAs`` inside a typed ``Person`` node is a stronger
    statement than the same URL appearing in a meta tag, so when both are
    present the JSON-LD one survives and keeps its subject.
    """
    rank = {"json-ld": 0, "rel-me": 1, "microdata": 2, "opengraph": 3, "link": 4}

    def pick(claims: list[Declared], key: Any) -> list[Declared]:
        best: dict[str, Declared] = {}
        for claim in sorted(claims, key=lambda c: rank.get(c.where, 9)):
            best.setdefault(key(claim), claim)
        return sorted(best.values(), key=lambda c: (rank.get(c.where, 9), c.value))

    out.accounts = pick(out.accounts, lambda c: c.value.rstrip("/").casefold())
    # The same name in a JSON-LD node and in ``og:site_name`` is one page
    # saying one thing twice, not two sources agreeing. Keeping both would
    # hand the graph a free corroboration off a single fetch, which is the
    # exact mistake ``Edge.weights`` exists to prevent one layer down.
    for bucket in ("people", "organisations", "emails", "phones", "addresses"):
        setattr(out, bucket, pick(getattr(out, bucket), lambda c: c.value.casefold()))
    # A role keeps its subject in the key: "Goldsmith" said of Racquel Tan and
    # "Bespoke jeweller" said of nobody in particular are two claims, and the
    # dossier pairs a title to a company only when a source tied them.
    for bucket in ("roles", "employers", "owners"):
        setattr(out, bucket, pick(getattr(out, bucket),
                                  lambda c: (c.value.casefold(), c.subject.casefold())))
