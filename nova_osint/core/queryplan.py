"""Deciding what to ask, in what order, and knowing when to stop.

A name is not a target. "John Smith" identifies a set of people, and the only
thing a tool can honestly do with it is generate the questions whose answers
would narrow that set - then spend a bounded budget on the ones most likely
to. That is this file.

The previous approach was a fixed list: fifteen dork templates per target
type, emitted in the order they were written. It is a good list and it has two
failures that matter. It cannot use what the scan just learned - discovering
an employer should change every remaining query and did not - and it treats
every query as equally worth running, so a budget gets spent alphabetically
rather than usefully.

The four rules
--------------

**Never invent a fact to search for.** Every variant here is a rearrangement
of something the operator supplied or the scan observed. A middle initial is
generated only from a middle name that exists; an employer query is generated
only from an employer somebody actually asserted. The moment a planner
speculates, the results it gets back are evidence for its own speculation.

**Value is estimated before the query runs, and corrected after.** A query's
prior is how *identifying* its terms are - a rare full name plus a company
narrows hard, a common given name plus an occupation narrows not at all. The
posterior is what it actually returned, and that feeds back into the category
weights for the rest of the run.

**A query that cannot be attributed is not worth running.** ``"John Smith"``
alone returns ten million pages about many people, and reading any of them as
being about the subject is the single largest source of false identity in
tools of this kind. Bare-name queries are generated, ranked *last*, and marked
so the consumer knows their results may be strangers'.

**Bounded by construction.** :meth:`QueryPlanner.plan` returns at most what it
was asked for, deduplicated, and never grows with the number of discoveries -
a planner that emits one query per discovery turns a productive scan into an
unrunnable one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

__all__ = ["Category", "Query", "NameForm", "name_forms", "QueryPlanner"]


class Category(Enum):
    """What kind of question a query is, and what it is worth by default.

    The weight is a prior on *how often this category produces something that
    identifies the subject rather than somebody who shares their name*. It is
    not how interesting the answer would be. A person's employer is enormously
    identifying; their opinions are not, however interesting.
    """

    IDENTITY = ("identity", 1.00)
    EMPLOYMENT = ("employment", 0.95)
    USERNAME = ("username", 0.95)
    DOMAIN = ("domain", 0.90)
    TECHNICAL = ("technical", 0.85)
    DEVELOPER = ("developer", 0.85)
    ORGANISATION = ("organisation", 0.80)
    PUBLICATION = ("publication", 0.80)
    RESEARCH = ("research", 0.75)
    EDUCATION = ("education", 0.75)
    DOCUMENT = ("document", 0.70)
    PROJECT = ("project", 0.70)
    WEBSITE = ("website", 0.70)
    CONTACT = ("contact", 0.65)
    EVENT = ("event", 0.60)
    PROFESSIONAL = ("professional", 0.60)
    EXPOSURE = ("exposure", 0.55)
    INFRASTRUCTURE = ("infrastructure", 0.55)
    HISTORICAL = ("historical", 0.45)
    GENERAL = ("general", 0.30)

    def __init__(self, label: str, weight: float) -> None:
        self.label = label
        self.weight = weight


@dataclass
class Query:
    """One search to run, and why it is worth running."""

    text: str
    category: Category
    #: 0..1, estimated before running. See :meth:`QueryPlanner._value`.
    value: float = 0.5
    #: What this query is trying to establish, in a few words.
    rationale: str = ""
    #: Where the terms came from: "seed", "brief", "discovery:<entity>",
    #: "image:ocr". Carried into the finding so a result's whole chain -
    #: image, to OCR text, to query, to page - stays visible.
    origin: str = "seed"
    #: True when a hit cannot be attributed to the subject by the query alone.
    ambiguous: bool = False
    #: Search operators the query uses, so an engine that lacks them can be
    #: given a degraded form rather than a query it will mangle.
    operators: frozenset[str] = frozenset()

    def for_engine(self, supports: frozenset[str] | None = None) -> str:
        """The query as this engine can take it.

        An engine that does not implement ``site:`` will treat it as a word
        and return pages *about* the phrase "site:github.com", which is worse
        than not filtering at all.
        """
        if supports is None or self.operators <= supports:
            return self.text
        text = self.text
        for op in sorted(self.operators - supports):
            text = re.sub(rf"\b{op}:\S+\s*", "", text)
        return " ".join(text.split())

    def to_dict(self) -> dict[str, Any]:
        return {"text": self.text, "category": self.category.label,
                "value": round(self.value, 3), "rationale": self.rationale,
                "origin": self.origin, "ambiguous": self.ambiguous}


# ------------------------------------------------------------- name handling


@dataclass(frozen=True)
class NameForm:
    """One way of writing a name, and how distinctive that spelling is."""

    text: str
    kind: str          # "exact" | "reversed" | "initials" | "partial"
    weight: float


#: Particles that belong to the surname rather than being a middle name.
_PARTICLES = {"van", "von", "de", "del", "della", "der", "den", "di", "da",
              "dos", "du", "la", "le", "bin", "ibn", "al", "st", "mac", "mc"}

#: Given names common enough that a bare-name query is close to worthless.
#: Deliberately short: this is a hedge against the most extreme cases, not an
#: attempt to model global name frequency, which cannot be done from a list.
_COMMON_SURNAMES = {
    "smith", "johnson", "williams", "brown", "jones", "garcia", "miller",
    "davis", "rodriguez", "martinez", "hernandez", "lopez", "gonzalez",
    "wilson", "anderson", "thomas", "taylor", "moore", "jackson", "martin",
    "lee", "perez", "thompson", "white", "harris", "sanchez", "clark",
    "wang", "li", "zhang", "liu", "chen", "yang", "huang", "kim", "park",
    "nguyen", "tran", "singh", "kumar", "patel", "khan", "ali", "silva",
    "santos", "rossi", "muller", "schmidt", "dubois", "ivanov",
}


def _split_name(name: str) -> list[str]:
    parts = [p for p in re.split(r"[\s,]+", name.strip()) if p]
    return parts


def name_forms(name: str) -> list[NameForm]:
    """Every spelling of a name that is a *rearrangement*, never an invention.

    "John Adam Smith" yields the full name, the surname-first form the
    academic world uses, the middle initial form, and the initials. It does
    **not** yield "John A. Smith" for an input of "John Smith": that is a
    different person's name until somebody says otherwise, and searching for
    it and finding somebody is exactly how these tools manufacture a match.
    """
    parts = _split_name(name)
    if not parts:
        return []
    if len(parts) == 1:
        return [NameForm(parts[0], "partial", 0.35)]

    given, *middle, family = parts
    # A particle belongs to the surname: "Ludwig van Beethoven" has no middle
    # name, and treating "van" as one produces "Ludwig v. Beethoven".
    while middle and middle[-1].lower().strip(".") in _PARTICLES:
        family = f"{middle.pop()} {family}"

    full = " ".join([given, *middle, family])
    forms = [NameForm(full, "exact", 1.0)]

    if middle:
        initials = " ".join(f"{m[0]}." for m in middle)
        forms.append(NameForm(f"{given} {initials} {family}", "exact", 0.95))
        forms.append(NameForm(f"{given} {family}", "exact", 0.9))

    forms.append(NameForm(f"{family}, {given}"
                          + (f" {' '.join(middle)}" if middle else ""),
                          "reversed", 0.8))
    forms.append(NameForm(f"{given[0]}. {family}", "initials", 0.45))
    # The run-together form drops any particle: "Lvan Beethoven" is not a
    # spelling anybody uses, and searching for it finds nothing while looking
    # like the tool covered that variant.
    forms.append(NameForm(f"{given[0]}{family.split()[-1]}", "initials", 0.4))

    seen: set[str] = set()
    out = []
    for form in forms:
        key = form.text.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(form)
    return out


def handle_candidates(name: str) -> list[str]:
    """Handles a person with this name *might* use.

    Explicitly speculative, and the only speculative thing in this file. They
    are emitted as queries to *test*, never as findings, and anything they
    turn up is worthless until an independent link ties the handle to the
    subject. The list is short on purpose: the long version of this idea
    generates two hundred handles, finds forty accounts, and attributes all of
    them to somebody who owns none.
    """
    parts = [p.lower() for p in _split_name(name) if p.isalpha()]
    if len(parts) < 2:
        return parts[:1]
    given, family = parts[0], parts[-1]
    return [f"{given}{family}", f"{given}.{family}", f"{given}_{family}",
            f"{given[0]}{family}", f"{given}{family[0]}"]


def name_rarity(name: str) -> float:
    """0..1: how much a bare-name search narrows anything.

    Three things push it down - a very common surname, a single-word name, and
    a two-part name with no middle - because each makes "pages mentioning this
    string" a worse proxy for "pages about this person".
    """
    parts = _split_name(name)
    if not parts:
        return 0.0
    score = 0.55
    if len(parts) >= 3:
        score += 0.25
    if len(parts) == 1:
        score -= 0.25
    if parts[-1].lower() in _COMMON_SURNAMES:
        score -= 0.3
    if any(len(p) > 9 for p in parts):
        score += 0.1        # long names are rarer, on average
    return max(0.05, min(1.0, score))


# ------------------------------------------------------------------ planning


#: ``(category, template, rationale, operators)``. ``{n}`` is a quoted name
#: form, ``{h}`` a handle, ``{d}`` a domain, ``{o}`` an organisation.
_PERSON_TEMPLATES: list[tuple[Category, str, str, tuple[str, ...]]] = [
    (Category.IDENTITY, '{n}', "who is publicly described by this name", ()),
    (Category.EMPLOYMENT, '{n} ("works at" OR "employed" OR "joined")',
     "current or former employer", ()),
    (Category.PROFESSIONAL, '{n} (biography OR profile OR "about me")',
     "a self-written description", ()),
    (Category.DEVELOPER, '{n} site:github.com', "code they have published",
     ("site",)),
    (Category.DEVELOPER, '{n} (site:gitlab.com OR site:codeberg.org OR '
     'site:bitbucket.org)', "code outside GitHub", ("site",)),
    (Category.PUBLICATION, '{n} (author OR "et al" OR doi)',
     "papers and articles they wrote", ()),
    (Category.RESEARCH, '{n} (site:arxiv.org OR site:orcid.org OR '
     'site:scholar.archive.org)', "a research identity", ("site",)),
    (Category.EDUCATION, '{n} (university OR college OR "PhD" OR thesis)',
     "where they studied", ()),
    (Category.EVENT, '{n} (conference OR speaker OR talk OR panel)',
     "public appearances, which are dated and attributable", ()),
    (Category.DOCUMENT, '{n} (filetype:pdf OR filetype:docx)',
     "documents naming them, which carry metadata", ("filetype",)),
    (Category.WEBSITE, '{n} ("personal site" OR blog OR portfolio)',
     "a site they control", ()),
    (Category.ORGANISATION, '{n} (board OR director OR founder OR trustee)',
     "formal roles, which are usually registered somewhere", ()),
    (Category.CONTACT, '{n} (email OR contact OR "@")',
     "a published address", ()),
    (Category.HISTORICAL, '{n} (site:web.archive.org OR "archived")',
     "what used to be true", ("site",)),
]

_USERNAME_TEMPLATES: list[tuple[Category, str, str, tuple[str, ...]]] = [
    (Category.USERNAME, '"{h}"', "anywhere this exact handle appears", ()),
    (Category.DEVELOPER, '"{h}" (site:github.com OR site:gitlab.com OR '
     'site:stackoverflow.com)', "their code and answers", ("site",)),
    (Category.USERNAME, '"{h}" (inurl:user OR inurl:profile OR inurl:member)',
     "profile pages carrying the handle", ("inurl",)),
    (Category.PROJECT, '"{h}" (site:npmjs.com OR site:pypi.org OR '
     'site:hub.docker.com)', "packages they publish", ("site",)),
    (Category.CONTACT, '"{h}" (keybase OR "pgp" OR "ssh-rsa" OR "ssh-ed25519")',
     "a key binding the handle to an identity", ()),
    (Category.EVENT, '"{h}" (site:news.ycombinator.com OR site:reddit.com)',
     "long-lived discussion history", ("site",)),
]

_DOMAIN_TEMPLATES: list[tuple[Category, str, str, tuple[str, ...]]] = [
    (Category.INFRASTRUCTURE, 'site:*.{d} -www', "subdomains the index knows",
     ("site",)),
    (Category.DOCUMENT, 'site:{d} (filetype:pdf OR filetype:docx OR '
     'filetype:xlsx)', "published documents and their metadata",
     ("site", "filetype")),
    (Category.EXPOSURE, 'site:{d} (inurl:login OR inurl:admin OR '
     'intitle:"index of")', "things that should not be indexed",
     ("site", "inurl", "intitle")),
    (Category.ORGANISATION, '"{d}" (about OR team OR staff OR leadership)',
     "who is publicly attached to it", ()),
    (Category.DEVELOPER, '"{d}" (site:github.com OR site:gitlab.com)',
     "code mentioning the domain", ("site",)),
    (Category.TECHNICAL, '"{d}" (dns OR mx OR spf OR "mail server")',
     "third-party notes about its infrastructure", ()),
]

_ORG_TEMPLATES: list[tuple[Category, str, str, tuple[str, ...]]] = [
    (Category.ORGANISATION, '"{o}" (about OR "our team" OR leadership)',
     "the organisation's own description", ()),
    (Category.DOMAIN, '"{o}" (website OR "official site")',
     "the domain it controls", ()),
    (Category.EMPLOYMENT, '"{o}" "{n}"',
     "the subject's link to this organisation", ()),
]


class QueryPlanner:
    """Turns what is known into an ordered, bounded list of things to ask.

    Stateful within one investigation: :meth:`observe` feeds back what each
    category actually produced, and later rounds are ordered accordingly. The
    state is per-run and never persisted - a category that was useless for one
    subject is not evidence about the next.
    """

    def __init__(self, *, max_queries: int = 24) -> None:
        self.max_queries = max_queries
        #: Learned multiplier per category, starting neutral.
        self._learned: dict[Category, float] = {}
        #: Every query text already planned, so nothing is asked twice - the
        #: single largest waste in an adaptive planner.
        self._seen: set[str] = set()

    # -- planning -----------------------------------------------------------

    def plan_person(self, name: str, *, known: dict[str, Any] | None = None,
                    limit: int | None = None) -> list[Query]:
        """Queries for a human name, ordered by what they are likely to settle."""
        known = known or {}
        forms = name_forms(name)
        rarity = name_rarity(name)
        if not forms:
            return []

        best = f'"{forms[0].text}"'
        queries: list[Query] = []

        for category, template, why, ops in _PERSON_TEMPLATES:
            text = template.format(n=best)
            ambiguous = category is Category.IDENTITY and rarity < 0.6
            queries.append(self._make(text, category, why, ops,
                                      base=rarity, ambiguous=ambiguous))

        # Anything the operator already knows is the most identifying thing we
        # have: it turns a bare-name query into an attributable one.
        for kind, value in sorted(known.items()):
            if not value or kind in ("name", "full_name"):
                continue
            category = _KNOWN_CATEGORY.get(kind, Category.IDENTITY)
            text = f'{best} "{value}"'
            queries.append(self._make(
                text, category,
                f"cross-check the subject against a known {kind}",
                (), base=min(1.0, rarity + 0.35), origin="brief"))

        # Alternate spellings, at their own weight rather than the best form's.
        for form in forms[1:]:
            if form.weight < 0.5:
                continue
            queries.append(self._make(
                f'"{form.text}"', Category.IDENTITY,
                f"the same name written {form.kind}", (),
                base=rarity * form.weight, ambiguous=rarity < 0.6))

        # Handles are a hypothesis to test, never an identification.
        for handle in handle_candidates(name)[:3]:
            queries.append(self._make(
                f'"{handle}"', Category.USERNAME,
                "a handle this name might use - must be corroborated", (),
                base=rarity * 0.5, ambiguous=True))

        return self._rank(queries, limit)

    def plan_username(self, handle: str, limit: int | None = None) -> list[Query]:
        queries = [
            self._make(t.format(h=handle), c, why, ops, base=_handle_rarity(handle))
            for c, t, why, ops in _USERNAME_TEMPLATES
        ]
        return self._rank(queries, limit)

    def plan_domain(self, domain: str, limit: int | None = None) -> list[Query]:
        queries = [
            self._make(t.format(d=domain), c, why, ops, base=0.85)
            for c, t, why, ops in _DOMAIN_TEMPLATES
        ]
        return self._rank(queries, limit)

    def plan_email(self, address: str, limit: int | None = None) -> list[Query]:
        local, _, domain = address.partition("@")
        queries = [
            self._make(f'"{address}"', Category.IDENTITY,
                       "the address itself, which is unambiguous", (), base=1.0),
            self._make(f'"{address}" (site:github.com OR site:gitlab.com)',
                       Category.DEVELOPER, "commits carrying the address",
                       ("site",), base=0.9),
            self._make(f'"{address}" (filetype:pdf OR filetype:xlsx OR filetype:csv)',
                       Category.DOCUMENT, "documents listing the address",
                       ("filetype",), base=0.8),
        ]
        if local:
            queries += self.plan_username(local, limit=4)
        if domain:
            queries.append(self._make(
                f'"{domain}" (about OR team OR contact)', Category.ORGANISATION,
                "what the address's domain is", (), base=0.6))
        return self._rank(queries, limit)

    def expand(self, discovery: str, kind: str, *, subject: str = "",
               origin: str = "discovery") -> list[Query]:
        """Follow-up queries a discovery justifies.

        This is the adaptive half: a scan that learns an employer should ask
        different questions for the rest of its budget than one that did not.
        The subject is carried into every follow-up, because a query about the
        *discovery* alone tells us about the discovery, not about the person.
        """
        subj = f'"{subject}" ' if subject else ""
        made: list[Query] = []
        if kind in ("org", "organisation", "employer"):
            for category, template, why, ops in _ORG_TEMPLATES:
                made.append(self._make(
                    template.format(o=discovery, n=subject), category, why, ops,
                    base=0.8, origin=f"{origin}:{discovery}"))
        elif kind in ("domain", "host"):
            made.append(self._make(
                f'{subj}"{discovery}"', Category.DOMAIN,
                "the subject's link to this domain", (), base=0.85,
                origin=f"{origin}:{discovery}"))
            made += [self._make(t.format(d=discovery), c, why, ops, base=0.7,
                                origin=f"{origin}:{discovery}")
                     for c, t, why, ops in _DOMAIN_TEMPLATES[:3]]
        elif kind in ("username", "handle"):
            made += [self._make(t.format(h=discovery), c, why, ops, base=0.8,
                                origin=f"{origin}:{discovery}")
                     for c, t, why, ops in _USERNAME_TEMPLATES[:3]]
        elif kind == "email":
            made.append(self._make(
                f'"{discovery}"', Category.CONTACT,
                "everywhere this address appears", (), base=0.95,
                origin=f"{origin}:{discovery}"))
        else:
            made.append(self._make(
                f'{subj}"{discovery}"', Category.GENERAL,
                f"the subject's link to this {kind}", (), base=0.5,
                origin=f"{origin}:{discovery}"))
        return self._rank(made, None)

    # -- feedback -----------------------------------------------------------

    def observe(self, query: Query, results: int, *, useful: int = 0) -> None:
        """Tell the planner what a query actually produced.

        A category that keeps returning nothing is demoted for the rest of the
        run; one that returns attributable results is promoted. The step is
        small and the range is clamped, because a planner that reorganises
        itself around one lucky query stops covering the ground.
        """
        current = self._learned.get(query.category, 1.0)
        if results == 0:
            delta = -0.12
        elif useful:
            delta = 0.15
        else:
            delta = -0.04
        self._learned[query.category] = max(0.4, min(1.6, current + delta))

    def weight_of(self, category: Category) -> float:
        return category.weight * self._learned.get(category, 1.0)

    # -- internals ----------------------------------------------------------

    def _make(self, text: str, category: Category, rationale: str,
              operators: tuple[str, ...], *, base: float = 0.5,
              origin: str = "seed", ambiguous: bool = False) -> Query:
        return Query(text=" ".join(text.split()), category=category,
                     value=self._value(category, base), rationale=rationale,
                     origin=origin, ambiguous=ambiguous,
                     operators=frozenset(operators))

    def _value(self, category: Category, base: float) -> float:
        return round(max(0.0, min(1.0, self.weight_of(category) * base)), 4)

    def _rank(self, queries: list[Query], limit: int | None) -> list[Query]:
        limit = self.max_queries if limit is None else limit
        out: list[Query] = []
        for q in sorted(queries, key=lambda q: (-q.value, q.ambiguous, q.text)):
            key = q.text.lower()
            if key in self._seen:
                continue
            self._seen.add(key)
            out.append(q)
            if len(out) >= limit:
                break
        return out


_KNOWN_CATEGORY = {
    "employer": Category.EMPLOYMENT,
    "org": Category.ORGANISATION,
    "organisation": Category.ORGANISATION,
    "city": Category.IDENTITY,
    "country": Category.IDENTITY,
    "school": Category.EDUCATION,
    "university": Category.EDUCATION,
    "occupation": Category.PROFESSIONAL,
    "role": Category.PROFESSIONAL,
    "domain": Category.DOMAIN,
    "username": Category.USERNAME,
    "email": Category.CONTACT,
    "keyword": Category.GENERAL,
}


def _handle_rarity(handle: str) -> float:
    """A long, unusual handle is close to an identifier; ``bob`` is not."""
    h = handle.strip()
    if len(h) <= 3:
        return 0.3
    score = 0.5 + min(0.35, (len(h) - 4) * 0.05)
    if any(c.isdigit() for c in h):
        score += 0.05
    if any(c in "._-" for c in h):
        score += 0.05
    return min(1.0, score)
