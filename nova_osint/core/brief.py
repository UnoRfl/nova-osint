"""The brief: everything you already know about the subject, before scanning.

NOVA started as "one target in, findings out". That is the wrong shape for the
question people actually bring to an OSINT tool, which is almost never *"tell me
about this handle"* and almost always *"I know these six things about a person -
which account, which profile, which company is actually theirs?"*

A brief is those six things. It is deliberately **not** configuration: a
:class:`~nova_osint.core.config.Config` holds how the tool should behave, a
brief holds assertions about the world that the tool is going to try to confirm
or contradict.

Why a brief changes what the tool can do
----------------------------------------

One seed can only ever produce candidates. Two seeds can *discriminate* between
them. If you know a name and a city, a name search returning forty people stops
being forty equal leads the moment thirty-nine of them are on the wrong
continent. The graph already merges entities by canonical value and already adds
independent log-odds - it simply never had more than one starting point to work
from. The brief supplies them.

The three rules this file is built around
-----------------------------------------

**A claim's weight is how *identifying* it is, not how confident you are in it.**
You may be completely certain of someone's first name and it still tells you
almost nothing, because millions of people share it. :data:`POWER` is a table of
how much a match narrows the field, and a full name is near the bottom of it.
That is this tool's whole thesis, expressed as arithmetic.

**Confirming and contradicting are not mirror images.** People move city, change
employer and let profiles rot, so a stale "works at" disagreeing with your brief
is weak evidence of anything. Nobody changes their date of birth. Every claim
kind therefore carries a *pair* of weights, and the disconfirming one is usually
the smaller. Treating them as symmetric is how a tool talks itself out of the
right answer because someone moved house.

**Derived claims are not independent evidence.** The local part of an email is a
plausible handle and it is worth trying - but if the handle matched *because* it
came from the email, that is one observation, not two, and adding both weights
counts the same fact twice. Derived claims carry their origin and the resolver
discounts them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .models import TargetType

# ---------------------------------------------------------------------------
# what a brief can contain
# ---------------------------------------------------------------------------


class ClaimKind(str, Enum):
    """A thing you can tell NOVA about the subject.

    Two families, deliberately in one enum because the resolver treats them
    alike when scoring:

    *Identifiers* are things that are (nearly) unique and can also be **scanned
    from** - an email, a handle, a phone, a domain. They seed the investigation
    and they discriminate between its results.

    *Attributes* describe the subject but cannot be looked up on their own - a
    city, an employer, a date of birth. They never seed anything. Their entire
    job is to tell two candidates apart, which is the job that mattered.
    """

    # --- identifiers (seedable) ------------------------------------------
    NAME = "name"              # a human name, or an organisation's name
    EMAIL = "email"
    USERNAME = "username"
    PHONE = "phone"
    DOMAIN = "domain"
    URL = "url"
    IP = "ip"

    # --- attributes (discriminators only) --------------------------------
    ORG = "org"                # employer, or the company being investigated
    ROLE = "role"              # job title / occupation
    CITY = "city"
    COUNTRY = "country"
    SCHOOL = "school"
    BORN = "born"              # date of birth, or a company's founding date
    LANGUAGE = "language"
    KEYWORD = "keyword"        # free text that should appear in a real profile


#: Claim kinds that can start a scan, and the target type they start it as.
#: Everything absent from this map is a discriminator and nothing else.
SEEDABLE: dict[ClaimKind, TargetType] = {
    ClaimKind.NAME: TargetType.PERSON,
    ClaimKind.EMAIL: TargetType.EMAIL,
    ClaimKind.USERNAME: TargetType.USERNAME,
    ClaimKind.PHONE: TargetType.PHONE,
    ClaimKind.DOMAIN: TargetType.DOMAIN,
    ClaimKind.URL: TargetType.URL,
    ClaimKind.IP: TargetType.IP,
}


@dataclass(frozen=True)
class Power:
    """How much a claim of this kind moves the needle, in nats of log-odds.

    ``confirm`` is added when a candidate matches, ``contradict`` (negative)
    when it demonstrably does not. Calibrated against the same anchors as
    :data:`nova_osint.core.graph.EVIDENCE` so the two can be summed: +7 is
    "a private key would have to be shared to fake it", +1 is "consistent, and
    also consistent with coincidence", 0 is no information.
    """

    confirm: float
    contradict: float
    why: str


#: The identifying power of each kind of claim.
#:
#: The numbers are judgements, collected here so they can be argued with and
#: tested rather than scattered through the resolver. Two things drive them:
#: how many people share a value of this kind, and how likely a *stale or
#: incomplete* public profile is to disagree with a true one.
#:
#: That second factor is why the pairs are asymmetric. An employer confirming
#: is worth real weight; an employer disagreeing is worth almost nothing,
#: because half the profiles on the internet name a job their owner left years
#: ago. A date of birth is the opposite: rarely stated, never changed, so it
#: is strong in both directions.
POWER: dict[ClaimKind, Power] = {
    ClaimKind.EMAIL: Power(6.5, -1.5,
                           "an address belongs to one mailbox"),
    ClaimKind.PHONE: Power(6.0, -1.5,
                           "a number belongs to one line at a time"),
    ClaimKind.DOMAIN: Power(5.0, -1.0,
                            "a registrable name has one owner"),
    ClaimKind.URL: Power(5.0, -1.0, "a page has one author"),
    ClaimKind.IP: Power(3.0, -0.5,
                        "addresses are shared and reassigned constantly"),
    ClaimKind.USERNAME: Power(4.0, -0.8,
                              "handles are reused across platforms by their "
                              "owner, and squatted by others"),
    ClaimKind.BORN: Power(4.5, -4.0,
                          "rarely published, and never revised"),
    ClaimKind.ORG: Power(2.0, -0.3,
                         "strong when it matches; people change jobs and "
                         "profiles go stale, so disagreement means little"),
    ClaimKind.SCHOOL: Power(2.0, -0.4,
                            "as with an employer, but people rarely have many"),
    ClaimKind.CITY: Power(1.5, -0.8,
                          "narrows hard, but people move and profiles lag"),
    ClaimKind.ROLE: Power(1.2, -0.3, "many people share a job title"),
    ClaimKind.COUNTRY: Power(0.6, -1.2,
                             "confirms little on its own; the wrong continent "
                             "is a real argument against"),
    ClaimKind.LANGUAGE: Power(0.3, -0.4, "weak either way"),
    ClaimKind.KEYWORD: Power(1.0, 0.0,
                             "presence is mild support; absence is not "
                             "evidence, so it never counts against"),
    # A name is the weakest identifier in the table, on purpose. It is the
    # thing users most expect to be decisive and the thing that least is.
    ClaimKind.NAME: Power(1.0, -1.5,
                          "a name identifies a set of people, not a person"),
}

#: A given name on its own - "Ryan" rather than "Ryan Rafael". Scored far below
#: a full name because the field it narrows to is enormous.
_LONE_NAME_POWER = Power(0.2, -0.6, "a single given name narrows almost nothing")


@dataclass
class Claim:
    """One thing you told NOVA, canonicalised and weighed."""

    kind: ClaimKind
    value: str
    #: The value as typed, kept because how something was written is evidence.
    raw: str = ""
    #: Set when NOVA worked this out from another claim rather than being told
    #: it - the local part of an email, the domain of a URL. Carries the kind
    #: it came from so the resolver can refuse to count both as independent.
    derived_from: ClaimKind | None = None
    #: The user's own confidence. A claim they flagged as uncertain still gets
    #: tested; it just cannot carry its full weight.
    certain: bool = True

    def __post_init__(self) -> None:
        if not self.raw:
            self.raw = self.value

    @property
    def derived(self) -> bool:
        return self.derived_from is not None

    @property
    def power(self) -> Power:
        base = POWER.get(self.kind, Power(1.0, -0.5, ""))
        if self.kind is ClaimKind.NAME and len(self.value.split()) < 2:
            base = _LONE_NAME_POWER
        if self.certain:
            return base
        # Half weight in both directions. An uncertain claim that matches is
        # still worth something, and one that does not match must not be
        # allowed to bury the right candidate.
        return Power(base.confirm * 0.5, base.contradict * 0.5, base.why)

    @property
    def seedable(self) -> bool:
        return self.kind in SEEDABLE

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind.value, "value": self.value, "raw": self.raw,
                "derived_from": self.derived_from.value if self.derived_from else None,
                "certain": self.certain}


@dataclass
class Brief:
    """Everything known about one subject at the start of an investigation."""

    claims: list[Claim] = field(default_factory=list)
    #: What the subject is: a person, or an organisation. Changes which
    #: attributes make sense and how the report is headed.
    subject_kind: str = "person"

    # -- construction -------------------------------------------------------

    def add(self, kind: ClaimKind | str, value: str, *,
            derived_from: ClaimKind | None = None, certain: bool = True) -> Claim | None:
        """Add a claim, canonicalising it. Returns ``None`` if it was empty or
        a duplicate of one already held."""
        kind = ClaimKind(kind) if isinstance(kind, str) else kind
        raw = (value or "").strip()
        if not raw:
            return None
        canon = canonical(kind, raw)
        if not canon:
            return None
        for existing in self.claims:
            if existing.kind is kind and existing.value == canon:
                # Told twice, or derived from something already stated. Keep
                # whichever is the stronger provenance: a fact the user gave
                # directly outranks the same fact NOVA worked out.
                if existing.derived and derived_from is None:
                    existing.derived_from = None
                return None
        claim = Claim(kind=kind, value=canon, raw=raw,
                      derived_from=derived_from, certain=certain)
        self.claims.append(claim)
        return claim

    # -- reading ------------------------------------------------------------

    def of(self, kind: ClaimKind) -> list[Claim]:
        return [c for c in self.claims if c.kind is kind]

    def first(self, kind: ClaimKind) -> str:
        found = self.of(kind)
        return found[0].value if found else ""

    @property
    def seeds(self) -> list[Claim]:
        """The claims a scan can start from, strongest identifier first.

        Ordered so the most identifying seed is expanded first: with a budget
        that runs out, what you want spent is the email lookup, not the name
        search that was always going to return forty people.
        """
        return sorted((c for c in self.claims if c.seedable),
                      key=lambda c: (-c.power.confirm, c.derived, c.kind.value))

    @property
    def discriminators(self) -> list[Claim]:
        """Claims held back to tell candidates apart rather than to scan from.

        Every claim discriminates - an email you seeded from is also an email a
        candidate either has or does not. This is simply the whole list, which
        is stated explicitly because the first version of this returned only
        the non-seedable ones and quietly threw away the strongest evidence in
        the brief.
        """
        return list(self.claims)

    @property
    def label(self) -> str:
        """What to call the subject in output."""
        for kind in (ClaimKind.NAME, ClaimKind.EMAIL, ClaimKind.USERNAME,
                     ClaimKind.DOMAIN, ClaimKind.PHONE, ClaimKind.URL):
            found = self.of(kind)
            if found:
                return found[0].raw
        return "unknown subject"

    def __len__(self) -> int:
        return len(self.claims)

    def __bool__(self) -> bool:
        return bool(self.claims)

    def to_dict(self) -> dict[str, Any]:
        return {"subject_kind": self.subject_kind,
                "claims": [c.to_dict() for c in self.claims]}

    # -- derivation ---------------------------------------------------------

    def expand(self) -> Brief:
        """Work out what else the brief implies, and add it as derived claims.

        Borrowed in spirit from Metasploit's option *fallbacks*, where an
        unset ``SMBUser`` falls back to a generic ``Username`` rather than the
        module simply failing. Here an unstated handle falls back to the local
        part of a known address, and an unstated domain to the host of a known
        URL, so a brief that names one thing gets the lookups that imply it.

        Everything added is marked ``derived_from``, because a handle that came
        out of an address is not a second independent observation of that
        person and must not be scored as one.
        """
        for claim in list(self.claims):
            if claim.kind is ClaimKind.EMAIL and "@" in claim.value:
                local, _, domain = claim.value.partition("@")
                # Tags are how one mailbox hands out many addresses; the handle
                # is the part before the tag.
                local = local.split("+")[0]
                if _USERNAME_SHAPED.match(local):
                    self.add(ClaimKind.USERNAME, local,
                             derived_from=ClaimKind.EMAIL)
                if domain and not _is_free_mail(domain):
                    # Only a domain the subject might actually be connected to.
                    # Deriving "gmail.com" from an address and then scanning it
                    # profiles Google, which is nobody's intention.
                    self.add(ClaimKind.DOMAIN, domain,
                             derived_from=ClaimKind.EMAIL)
            elif claim.kind is ClaimKind.URL:
                from .http import hostname_of

                host = hostname_of(claim.value)
                if host:
                    self.add(ClaimKind.DOMAIN, host, derived_from=ClaimKind.URL)
        return self


# ---------------------------------------------------------------------------
# canonicalisation
# ---------------------------------------------------------------------------

_USERNAME_SHAPED = re.compile(r"^[A-Za-z0-9._-]{2,64}$")
_WS = re.compile(r"\s+")

#: Mailbox providers whose domain says nothing about its users. Deriving a
#: domain claim from an address at one of these would put "the whole of Gmail"
#: in the brief as something to investigate.
_FREE_MAIL = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "msn.com", "yahoo.com", "ymail.com", "aol.com", "icloud.com", "me.com",
    "mac.com", "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net",
    "mail.com", "zoho.com", "yandex.ru", "yandex.com", "tutanota.com",
    "tuta.io", "fastmail.com", "hey.com", "qq.com", "163.com", "126.com",
    "naver.com", "daum.net", "seznam.cz", "web.de", "t-online.de",
})


def _is_free_mail(domain: str) -> bool:
    return domain.casefold() in _FREE_MAIL


def canonical(kind: ClaimKind, value: str) -> str:
    """One spelling per claim, so "KL" and "kl" are one thing.

    Reuses :mod:`nova_osint.core.entities` for anything that is also a graph
    node, because a claim and the entity it will be compared against have to
    canonicalise identically or the comparison silently never matches. That is
    the whole reason this dispatches rather than lowercasing everything.
    """
    from .entities import EntityType
    from .entities import canonical as entity_canonical

    text = _WS.sub(" ", (value or "").strip())
    if not text:
        return ""

    as_entity = {
        ClaimKind.EMAIL: EntityType.EMAIL,
        ClaimKind.USERNAME: EntityType.USERNAME,
        ClaimKind.PHONE: EntityType.PHONE,
        ClaimKind.DOMAIN: EntityType.DOMAIN,
        ClaimKind.URL: EntityType.URL,
        ClaimKind.IP: EntityType.IP,
        ClaimKind.NAME: EntityType.PERSON,
        ClaimKind.ORG: EntityType.ORG,
    }.get(kind)
    if as_entity is not None:
        try:
            canon = entity_canonical(as_entity, text)
        except Exception:
            canon = ""
        if canon:
            return canon
    if kind is ClaimKind.BORN:
        return _date(text)
    if kind is ClaimKind.COUNTRY:
        # "UK" and "United Kingdom of Great Britain and Ireland" share no whole
        # word, so before this they compared as a *contradiction* and pushed
        # the right candidate down. Resolving to one name first is a
        # correctness fix, not tidiness.
        from .vocab import country as canon_country

        return (canon_country(text) or text).casefold()
    if kind is ClaimKind.LANGUAGE:
        from .vocab import language as canon_language

        return (canon_language(text) or text).casefold()
    # Free text: case-folded, whitespace-collapsed. Not stripped of
    # punctuation - "St. Andrews" and "St Andrews" are compared loosely by the
    # resolver, which is the right place for fuzziness, not here.
    return text.casefold()


_DATE_PATTERNS = (
    (re.compile(r"^(\d{4})-(\d{1,2})-(\d{1,2})$"), (1, 2, 3)),
    (re.compile(r"^(\d{1,2})/(\d{1,2})/(\d{4})$"), (3, 2, 1)),
    (re.compile(r"^(\d{4})$"), (1, None, None)),
)


def _date(text: str) -> str:
    """ISO-8601 where possible, the year alone where that is all there is.

    A year-only claim is genuinely useful - it separates two people with the
    same name born a decade apart - so it is kept rather than rejected, and
    the resolver knows to compare only as much as both sides state.
    """
    for pattern, order in _DATE_PATTERNS:
        m = pattern.match(text.strip())
        if not m:
            continue
        year = m.group(order[0])
        if order[1] is None:
            return year
        return f"{year}-{int(m.group(order[1])):02d}-{int(m.group(order[2])):02d}"
    return text.casefold()


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------

#: Spellings accepted for each claim kind on the command line and in brief
#: files, so nobody has to remember whether it is ``org`` or ``company``.
ALIASES: dict[str, ClaimKind] = {
    "name": ClaimKind.NAME, "fullname": ClaimKind.NAME,
    "person": ClaimKind.NAME, "subject": ClaimKind.NAME,
    "email": ClaimKind.EMAIL, "mail": ClaimKind.EMAIL,
    "address": ClaimKind.EMAIL,
    "username": ClaimKind.USERNAME, "user": ClaimKind.USERNAME,
    "handle": ClaimKind.USERNAME, "nick": ClaimKind.USERNAME,
    "phone": ClaimKind.PHONE, "tel": ClaimKind.PHONE,
    "mobile": ClaimKind.PHONE, "number": ClaimKind.PHONE,
    "domain": ClaimKind.DOMAIN, "site": ClaimKind.DOMAIN,
    "website": ClaimKind.DOMAIN,
    "url": ClaimKind.URL, "link": ClaimKind.URL, "profile": ClaimKind.URL,
    "ip": ClaimKind.IP,
    "org": ClaimKind.ORG, "company": ClaimKind.ORG,
    "employer": ClaimKind.ORG, "organisation": ClaimKind.ORG,
    "organization": ClaimKind.ORG, "works-at": ClaimKind.ORG,
    "role": ClaimKind.ROLE, "job": ClaimKind.ROLE, "title": ClaimKind.ROLE,
    "occupation": ClaimKind.ROLE,
    "city": ClaimKind.CITY, "town": ClaimKind.CITY,
    "location": ClaimKind.CITY, "lives-in": ClaimKind.CITY,
    "country": ClaimKind.COUNTRY, "nationality": ClaimKind.COUNTRY,
    "school": ClaimKind.SCHOOL, "university": ClaimKind.SCHOOL,
    "college": ClaimKind.SCHOOL, "educated-at": ClaimKind.SCHOOL,
    "born": ClaimKind.BORN, "dob": ClaimKind.BORN,
    "birthday": ClaimKind.BORN, "birthdate": ClaimKind.BORN,
    "founded": ClaimKind.BORN,
    "language": ClaimKind.LANGUAGE, "lang": ClaimKind.LANGUAGE,
    "keyword": ClaimKind.KEYWORD, "about": ClaimKind.KEYWORD,
    "bio": ClaimKind.KEYWORD, "note": ClaimKind.KEYWORD,
}


class BriefError(ValueError):
    """A brief that could not be understood. Carries advice, not just a fault."""


def parse_pair(text: str) -> tuple[ClaimKind, str, bool]:
    """``"city=Kuala Lumpur"`` -> ``(CITY, "Kuala Lumpur", True)``.

    A trailing ``?`` on the key marks the claim uncertain: ``city?=KL`` means
    "I think they are in KL". Uncertain claims are still tested - they just
    cannot carry full weight, and cannot bury a candidate on their own.
    """
    key, sep, value = text.partition("=")
    if not sep:
        raise BriefError(
            f"{text!r} is not a fact: write it as key=value, for example "
            f"name='Ada Lovelace' or city=Cambridge")
    key = key.strip().casefold().replace("_", "-")
    certain = True
    if key.endswith("?"):
        key, certain = key[:-1].strip(), False
    kind = ALIASES.get(key)
    if kind is None:
        known = ", ".join(sorted({k.value for k in ClaimKind}))
        raise BriefError(f"{key!r} is not something NOVA knows how to use. "
                         f"Try one of: {known}")
    if not value.strip():
        raise BriefError(f"{key!r} was given with no value")
    return kind, value.strip(), certain


def from_pairs(pairs: list[str], subject_kind: str = "person") -> Brief:
    """Build a brief from ``key=value`` strings, as the CLI collects them."""
    brief = Brief(subject_kind=subject_kind)
    for pair in pairs:
        kind, value, certain = parse_pair(pair)
        brief.add(kind, value, certain=certain)
    return brief


def from_mapping(data: dict[str, Any], subject_kind: str = "person") -> Brief:
    """Build a brief from a parsed JSON or YAML file.

    A value may be a string or a list of strings, because a subject routinely
    has two addresses or three handles and forcing one per file would make the
    format useless for the case it exists to serve.
    """
    brief = Brief(subject_kind=str(data.get("subject_kind") or subject_kind))
    for key, value in data.items():
        if key == "subject_kind":
            continue
        try:
            kind, _, certain = parse_pair(f"{key}=x")
        except BriefError as exc:
            raise BriefError(f"in the brief file: {exc}") from exc
        for item in (value if isinstance(value, (list, tuple)) else [value]):
            if item is None:
                continue
            brief.add(kind, str(item), certain=certain)
    return brief


def load(path: str) -> Brief:
    """Read a brief from a ``.json``, ``.yaml`` or ``.yml`` file."""
    import json
    from pathlib import Path

    text = Path(path).read_text("utf-8")
    if path.casefold().endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise BriefError(
                "reading a YAML brief needs PyYAML (pip install pyyaml); "
                "a JSON brief works with no extra packages") from exc
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise BriefError("a brief file must be a mapping of fact to value")
    return from_mapping(data)
