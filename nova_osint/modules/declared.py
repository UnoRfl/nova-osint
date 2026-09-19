"""Who a site says runs it: accounts, people, roles, and whether it trades.

The counterpart to the username sweep, and the answer to a complaint the sweep
can never fix. Facebook, Instagram, Threads and LinkedIn all refuse anonymous
profile lookups, so no catalogue can test them and NOVA correctly reported them
as *not checkable* - which reads, to anybody who is not the person who wrote it,
as "no accounts found".

But those four are exactly the platforms a business advertises, and a business
advertises them on its own website, in a machine-readable block put there for
search engines. The one path into the walled platforms is the one the subject
opened themselves.

So this module reads the site rather than the platforms:

* ``schema.org`` ``sameAs`` - the owner listing their own accounts in a typed
  field. Several per platform survive, because a business genuinely has a
  Facebook page *and* a Facebook profile, and collapsing them to one row was
  throwing away the second.
* ``jobTitle``, ``worksFor``, ``founder``, ``owner`` - occupation, and the
  stronger claim that the subject *is* the business rather than works at one.
  These land as ``<name>: occupation`` and ``<name>: employer`` findings, which
  is the shape :mod:`~nova_osint.core.biography` already reads, so the dossier
  fills in with no further wiring.
* ``LocalBusiness`` and its subtypes - the page asserting that a real business
  trades here, which is a different claim from "a company exists".
* Plain links and ``rel="me"``, because most small sites publish none of the
  above. Measured on the site this was built against: no JSON-LD, no
  microdata, and one click-to-chat link in the footer carrying a mobile number.

Everything is reported as **declared by a page**, with that page's URL. A page
saying "our founder is Jane Doe" is excellent evidence about the site and no
evidence whatsoever about a Jane Doe found somewhere else, and the difference
between those two readings is the whole discipline of this tool.
"""

from __future__ import annotations

import re
import urllib.parse

from ..core.entities import EntityType, is_handle_shaped
from ..core.models import Confidence, ScanResult, Severity, TargetType
from ..core.registry import Module, register
from ..core.structured import SiteIdentity, harvest, platform_of

#: Paths worth trying beyond the front page. Ordered by how often they carry an
#: identity block rather than by how common they are: a contact page names a
#: person and a phone number, a front page names the company.
IDENTITY_PATHS = ("/", "/about", "/about-us", "/contact", "/contact-us",
                  "/pages/about", "/pages/contact", "/team", "/our-story")

#: Stop after this many pages answered. The front page usually settles it, and
#: an investigation should not walk a site to find a second copy of the same
#: Instagram link.
MAX_PAGES = 4

#: Platform paths that are furniture, not an account.
_NOT_AN_ACCOUNT = frozenset({
    "", "sharer", "sharer.php", "share", "home", "login", "signup", "explore",
    "intent", "help", "privacy", "policies", "legal", "about", "settings",
})

_HANDLE = re.compile(r"^[A-Za-z0-9._-]{2,64}$")

#: Platforms whose profile path is not an account name. ``wa.me/6580562021``
#: is a *phone number*, and the first live run of this module turned it into a
#: username entity - which is the whole "a name is not a handle" failure again
#: wearing a different hat, and would have aimed a 481-site sweep at a mobile
#: number.
_PATH_IS_NOT_A_HANDLE = frozenset({"WhatsApp"})

#: An all-digit path segment is an internal profile id - ``facebook.com/
#: 61551234567890`` - not something any other site will know the subject by.
_ALL_DIGITS = re.compile(r"^\d+$")

#: A script, not a person. ``facebook.com/profile.php?id=…`` is a real account
#: whose last path segment matches every handle pattern ever written, and it
#: yielded the handle "profile.php".
_IS_A_FILE = re.compile(
    r"\.(php|html?|aspx?|jsp|cgi|json|xml|rss|atom|txt|keys|gpg|asc)$", re.I)


def _base(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")
    return "https://" + target.strip("/")


def _handle_in(url: str) -> str:
    """The account name inside a profile URL, or ``""`` when there is not one.

    ``facebook.com/profile.php?id=615…`` is a real account with no handle, and
    ``x.com/i/flow/login`` is not an account at all. Both must return empty
    rather than a plausible-looking string, because the return value is fed to
    :func:`~nova_osint.core.entities.is_handle_shaped` and from there to a
    481-site sweep.
    """
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return ""
    segments = [s for s in parts.path.split("/") if s]
    if not segments:
        return ""
    # ``linkedin.com/in/name`` and ``linkedin.com/company/name`` put the handle
    # second; everything else puts it first.
    candidate = segments[1] if segments[0].lower() in ("in", "company", "pages",
                                                       "groups", "people") \
        and len(segments) > 1 else segments[0]
    candidate = candidate.lstrip("@")
    if candidate.lower() in _NOT_AN_ACCOUNT or not _HANDLE.match(candidate):
        return ""
    if (_ALL_DIGITS.match(candidate) or _IS_A_FILE.search(candidate)
            or platform_of(url) in _PATH_IS_NOT_A_HANDLE):
        return ""
    return candidate


@register
class DeclaredIdentityModule(Module):
    name = "declared"
    title = "Declared identity"
    description = ("Social accounts, owner, occupation and business type as "
                   "published in the site's own structured data.")
    accepts = frozenset({TargetType.DOMAIN, TargetType.URL})
    active = True

    def run(self, target: str, result: ScanResult) -> None:
        base = _base(target)
        merged = SiteIdentity(url=base)
        read: list[str] = []

        for path in IDENTITY_PATHS:
            if len(read) >= MAX_PAGES:
                break
            url = base if path == "/" else base + path
            resp = self.http.get(url)
            if resp.status != 200 or not resp.text:
                continue
            read.append(url)
            self._absorb(merged, harvest(resp.text, url))

        if not read:
            result.error("no page on this site answered")
            return

        result.add("pages read", len(read), source="declared",
                   severity=Severity.INFO,
                   extra={"urls": read, "formats": sorted(merged.formats)})

        if not merged:
            # Said out loud, because "no accounts" and "this site publishes
            # nothing machine-readable and links to nobody" are different
            # facts and only the second one is true here.
            result.add("declared identity", "none published", source="declared",
                       severity=Severity.INFO, confidence=Confidence.CONFIRMED,
                       extra={"note": "the site publishes no structured identity "
                                      "data and links to no social platform; this "
                                      "is not evidence that no accounts exist"})
            return

        self._accounts(merged, result, base)
        self._who(merged, result)
        self._contacts(merged, result)
        self._business(merged, result)

    # -- collection ----------------------------------------------------------

    @staticmethod
    def _absorb(into: SiteIdentity, page: SiteIdentity) -> None:
        into.formats |= page.formats
        for bucket in ("accounts", "people", "organisations", "roles",
                       "employers", "owners", "emails", "phones", "addresses"):
            existing = getattr(into, bucket)
            known = {(c.value.casefold(), c.subject.casefold()) for c in existing}
            for claim in getattr(page, bucket):
                key = (claim.value.casefold(), claim.subject.casefold())
                if key not in known:
                    known.add(key)
                    existing.append(claim)
        for kind in page.business_types:
            if kind not in into.business_types:
                into.business_types.append(kind)

    # -- rendering -----------------------------------------------------------

    def _accounts(self, got: SiteIdentity, result: ScanResult, base: str) -> None:
        grouped = got.platforms
        if not grouped:
            return
        declared = sum(1 for c in got.accounts if c.where != "link")
        result.add(
            "social accounts", f"{len(got.accounts)} on {len(grouped)} platform(s)",
            source="declared", severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED if declared else Confidence.LIKELY,
            extra={"declared": declared, "linked_only": len(got.accounts) - declared},
        )
        for platform, claims in sorted(grouped.items()):
            for claim in claims:
                strong = claim.where != "link"
                # One row per account rather than per platform: a business has
                # a page and a profile, a person has a personal and a work
                # account, and the operator asked for all of them.
                result.add(
                    f"{platform} account", claim.value, source="declared",
                    url=claim.value,
                    severity=Severity.HIGH if strong else Severity.NOTABLE,
                    confidence=Confidence.LIKELY if strong else Confidence.POSSIBLE,
                    extra={
                        "basis": claim.where,
                        "declared_for": claim.subject or "the site",
                        "note": ("published by the site as its own account"
                                 if strong else
                                 "linked from the page; a link is a lead, not "
                                 "an assertion of ownership"),
                    },
                )
                handle = _handle_in(claim.value)
                if handle and is_handle_shaped(handle):
                    result.entity(
                        EntityType.USERNAME, handle,
                        relation="declared-account" if strong else "linked-account",
                        evidence="declared-account" if strong else "linked-account",
                        url=claim.value,
                        detail=f"{platform} account published on {base}",
                        group=f"declared@{base}",
                    )

    def _who(self, got: SiteIdentity, result: ScanResult) -> None:
        for claim in got.owners:
            result.add("site owner", claim.value, source="declared",
                       severity=Severity.HIGH, confidence=Confidence.LIKELY,
                       url=got.url, extra={"relation": claim.detail,
                                           "basis": claim.where})
            result.entity(EntityType.PERSON, claim.value, relation="owner",
                          evidence="site-owner", url=got.url,
                          detail=claim.detail or "named as owner of the site",
                          group=f"declared@{got.url}")
            # The dossier reads "<name>: employer"; saying it this way is what
            # gets an owner into the employment table rather than a loose note.
            if claim.subject and claim.subject != claim.value:
                result.add(f"{claim.value}: employer", claim.subject,
                           source="declared", severity=Severity.NOTABLE,
                           confidence=Confidence.LIKELY, url=got.url)
                result.add(f"{claim.value}: occupation",
                           f"{claim.detail.split(' of ')[0] or 'owner'}",
                           source="declared", severity=Severity.NOTABLE,
                           confidence=Confidence.LIKELY, url=got.url)

        for claim in got.people:
            if any(o.value.casefold() == claim.value.casefold() for o in got.owners):
                continue
            result.add("named on the site", claim.value, source="declared",
                       severity=Severity.NOTABLE, confidence=Confidence.POSSIBLE,
                       url=got.url, extra={"basis": claim.where,
                                           "note": "named by the page; the page "
                                                   "did not say in what capacity"})

        for claim in got.roles:
            who = claim.subject or claim.value
            label = f"{claim.subject}: occupation" if claim.subject else "stated role"
            result.add(label, claim.value, source="declared",
                       severity=Severity.NOTABLE, confidence=Confidence.LIKELY,
                       url=got.url, extra={"basis": claim.where, "subject": who})

        for claim in got.employers:
            label = f"{claim.subject}: employer" if claim.subject else "employer named"
            result.add(label, claim.value, source="declared",
                       severity=Severity.NOTABLE, confidence=Confidence.LIKELY,
                       url=got.url, extra={"basis": claim.where})
            result.entity(EntityType.ORG, claim.value, relation="employer",
                          evidence="declared-employer", url=got.url,
                          detail=f"named as employer of {claim.subject or 'someone'}",
                          group=f"declared@{got.url}")

        for claim in got.organisations:
            result.entity(EntityType.ORG, claim.value, relation="operator",
                          evidence="site-owner", url=got.url,
                          detail="the organisation the site presents itself as",
                          group=f"declared@{got.url}")

    def _contacts(self, got: SiteIdentity, result: ScanResult) -> None:
        for claim in got.emails:
            result.add("published email", claim.value, source="declared",
                       severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                       url=got.url, extra={"basis": claim.where})
            result.entity(EntityType.EMAIL, claim.value, relation="contact",
                          evidence="published-contact", url=got.url,
                          detail="address published in the site's own markup",
                          group=f"declared@{got.url}")
        for claim in got.phones:
            result.add("published phone", claim.value, source="declared",
                       severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                       url=got.url, extra={"basis": claim.where,
                                           "detail": claim.detail})
            result.entity(EntityType.PHONE, claim.value, relation="contact",
                          evidence="published-contact", url=got.url,
                          detail=claim.detail or "number published on the site",
                          group=f"declared@{got.url}")
        for claim in got.addresses:
            result.add("published address", claim.value, source="declared",
                       severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                       url=got.url, extra={"basis": claim.where})

    @staticmethod
    def _business(got: SiteIdentity, result: ScanResult) -> None:
        if not got.business_types:
            return
        pretty = ", ".join(sorted({t.title() for t in got.business_types}))
        result.add("trades as", pretty, source="declared", severity=Severity.HIGH,
                   confidence=Confidence.CONFIRMED, url=got.url,
                   extra={"note": "the site declares itself a trading business "
                                  "of this type, which is a stronger claim than "
                                  "a company merely existing",
                          "schema_types": sorted(got.business_types)})
