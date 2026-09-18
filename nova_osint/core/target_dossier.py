"""``generate_target_dossier`` - one investigation, consolidated into one subject.

Every renderer before this one is organised around *where a fact came from*.
``report`` groups by module, ``dossier`` groups by entity kind, ``biography``
groups by attribute label. All three are the right shape for checking the
tool's work and the wrong shape for answering the question the user actually
asked, which is "so what do you know about this person".

This module answers that, and answers it in **one object** rather than in six
sections a reader has to reconcile by hand.

What it does not do
-------------------

**It does not invent pairings.** When a subject has three employers and two job
titles, there is no honest way to say which title goes with which employer
unless a source said so. :func:`_employment` pairs them only when a source
carried them together or when there is exactly one of each; otherwise the
records stay unpaired and say so. The alternative - zipping the lists - fills a
dossier with plausible, checkable, wrong sentences, which is the worst possible
failure mode for this tool.

**It does not pick a winner.** Every field is an :class:`~.scoring.EvidenceSet`,
so two sources disagreeing about a date of birth produce two ranked values with
their sources attached, not one value and a deleted rival. The renderers print
the disagreement.

**It does not promote a fixture.** A value whose evidence type is synthetic is
carried through every layer still marked synthetic, and the Markdown report
refuses to render a dossier containing one without a banner saying so.

**It does not read credentials.** Exposure records go through
:func:`~..modules.exposure_parser.parse_exposure_metadata`, which cannot return
a password, hash or token. What it can return is the surrounding biographical
metadata, which is the part that belongs in a dossier.

Where the old capabilities went
-------------------------------

Nothing is replaced; this is a consolidation layer that reads what the existing
pipeline already produced:

============================  ===========================================
existing source               where it now appears
============================  ===========================================
``biography.extract``         identity.*, background.*
``socials.collect``           digital_footprint.linked_accounts
graph ``PHONE`` entities      identity.associated_phone_numbers
graph ``ORG`` entities        background.employment
``breaches`` / ``pwned``      digital_footprint.exposure_records
``brief.Brief`` claims        every field, at ``user_provided`` weight
``identity.Resolution``       ``subject_confidence`` and ``candidates``
``ModuleStatus`` gaps         ``collection_errors``
============================  ===========================================
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from ..modules.exposure_parser import parse_exposure_metadata
from . import biography, socials
from .entities import EntityType
from .models import Confidence, Investigation
from .scoring import Evidence, EvidenceSet, normalise, weight_for

# ---------------------------------------------------------------------------
# which kind of source a module counts as
# ---------------------------------------------------------------------------

#: Module/source name -> evidence type, checked as a prefix match.
#:
#: This is the one place that decides what a source is *worth*, and it is a
#: table rather than a rule so that every weight in a dossier can be traced to
#: a deliberate line here. A source not listed falls to ``public_web_profile``,
#: which is mid-range and honest about being a guess.
_SOURCE_KIND: tuple[tuple[str, str], ...] = (
    # Registries and encyclopaedias: an editor or a registrar stands behind it.
    ("wikidata", "verified_public_record"),
    ("rdap", "verified_public_record"),
    ("whois", "verified_public_record"),
    ("registry", "verified_public_record"),
    ("securitytrails", "verified_public_record"),
    # The platform itself answering about its own user.
    ("github", "official_profile"),
    ("gitlab", "official_profile"),
    ("keybase", "official_profile"),
    ("bluesky", "official_profile"),
    ("gravatar", "official_profile"),
    ("webfinger", "official_profile"),
    ("npm", "official_profile"),
    ("pypi", "official_profile"),
    ("hibp", "official_profile"),
    # A page that exists and says something, with nobody vouching for it.
    ("username", "public_web_profile"),
    ("web", "public_web_profile"),
    ("wayback", "public_web_profile"),
    ("social", "public_web_profile"),
    # Things this tool worked out itself. Never better than weak: a name
    # guessed from an email local part is a hypothesis, not a finding, and
    # weighting it as one is how "mailauth-reports" becomes a person's name.
    ("heuristic", "derived"),
    ("analysis", "derived"),
    ("parse", "derived"),
    ("local", "derived"),
    ("inferred", "derived"),
    ("fixture", "synthetic_fixture"),
    ("synthetic", "synthetic_fixture"),
)

#: Confidence floor by finding confidence. A source class can be downgraded by
#: the module's own uncertainty but never upgraded by it - a heuristic that is
#: sure of itself is still a heuristic.
_CONFIDENCE_CEILING = {
    Confidence.CONFIRMED: 1.00,
    Confidence.LIKELY: 0.70,
    Confidence.POSSIBLE: 0.50,
}


def evidence_type_for(source: str) -> str:
    """Which class of source *source* belongs to."""
    key = (source or "").strip().casefold()
    for prefix, kind in _SOURCE_KIND:
        if prefix in key:
            return kind
    return "public_web_profile"


#: Admiralty grade -> the module confidence it was rendered from. Used to read
#: ``biography.Value`` back, which stores the grade rather than the enum.
_GRADE_CONFIDENCE = {"B2": Confidence.CONFIRMED, "C3": Confidence.LIKELY,
                     "D3": Confidence.POSSIBLE}


def _evidence(value: str, source: str, *, grade: str = "C3",
              url: str | None = None, note: str = "",
              evidence_type: str | None = None) -> Evidence:
    """Build one :class:`Evidence`, scored from its source and its grade."""
    kind = evidence_type or evidence_type_for(source)
    confidence = min(
        weight_for(kind),
        _CONFIDENCE_CEILING.get(_GRADE_CONFIDENCE.get(grade, Confidence.LIKELY), 0.70),
    )
    return Evidence(value=str(value).strip(), source=source, confidence=confidence,
                    evidence_type=kind, url=url, note=note)


# ---------------------------------------------------------------------------
# target normalisation
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"^[^@\s]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_URL_RE = re.compile(r"^https?://", re.I)
_HANDLE_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


@dataclass
class TargetIdentifiers:
    """Everything the caller knows going in, normalised and typed.

    Deliberately *not* inferential. It will read the handle out of a profile
    URL the caller supplied, because that is parsing rather than guessing, but
    it will not derive a person's name from an email local part - that is how
    ``mailauth-reports@google.com`` became "Mailauth Reports" and then became
    the headline identity of a report about somebody else.
    """

    emails: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    display_names: list[str] = field(default_factory=list)
    profile_urls: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)

    def all_values(self) -> list[str]:
        return [*self.emails, *self.usernames, *self.display_names,
                *self.profile_urls, *self.phones]

    def to_dict(self) -> dict[str, Any]:
        return {"emails": self.emails, "usernames": self.usernames,
                "display_names": self.display_names,
                "profile_urls": self.profile_urls, "phones": self.phones}


def normalize_target_identifiers(*values: str | Iterable[str]) -> TargetIdentifiers:
    """Sort loose caller-supplied strings into typed, de-duplicated buckets.

    Accepts strings or iterables of strings, in any order and any mixture, so a
    caller does not have to tell the dossier what each of its inputs is.
    """
    out = TargetIdentifiers()
    flat: list[str] = []
    for value in values:
        if value is None:
            continue
        if isinstance(value, str):
            flat.append(value)
        else:
            flat.extend(str(v) for v in value if v)

    for raw in flat:
        text = str(raw).strip()
        if not text:
            continue
        if _EMAIL_RE.match(text):
            _push(out.emails, text.casefold())
        elif _URL_RE.match(text):
            _push(out.profile_urls, text)
            # Reading the handle out of a URL the caller gave us is parsing,
            # not inference, so it is safe to promote.
            handle = socials.handle_from(text)
            if handle and _HANDLE_RE.match(handle):
                _push(out.usernames, handle)
        elif re.fullmatch(r"[+()\d\s.-]{7,}", text):
            _push(out.phones, re.sub(r"[^\d+]", "", text))
        elif _HANDLE_RE.match(text) and " " not in text:
            _push(out.usernames, text)
        else:
            _push(out.display_names, text)
    return out


def _push(bucket: list[str], value: str) -> None:
    if value and value not in bucket:
        bucket.append(value)


# ---------------------------------------------------------------------------
# the dossier
# ---------------------------------------------------------------------------


@dataclass
class EducationRecord:
    """One school. ``degree`` and ``graduation_year`` are often absent."""

    school_name: str
    graduation_year: str | None = None
    degree: str | None = None
    evidence: list[Evidence] = field(default_factory=list)

    @property
    def confidence(self) -> float:
        return max((e.confidence for e in self.evidence), default=0.0)

    def to_dict(self) -> dict[str, Any]:
        return {"school_name": self.school_name,
                "graduation_year": self.graduation_year,
                "degree": self.degree,
                "confidence": round(self.confidence, 3),
                "evidence": [e.to_dict() for e in self.evidence]}


@dataclass
class EmploymentRecord:
    """One employer.

    ``role_paired`` is the honest flag: False means the role was found in the
    same investigation but no source tied it to *this* company, and the pairing
    is the reader's to make.
    """

    company: str
    role: str | None = None
    start_date: str | None = None
    end_date: str | None = None
    role_paired: bool = True
    evidence: list[Evidence] = field(default_factory=list)

    @property
    def confidence(self) -> float:
        return max((e.confidence for e in self.evidence), default=0.0)

    def to_dict(self) -> dict[str, Any]:
        return {"company": self.company, "role": self.role,
                "start_date": self.start_date, "end_date": self.end_date,
                "role_paired": self.role_paired,
                "confidence": round(self.confidence, 3),
                "evidence": [e.to_dict() for e in self.evidence]}


@dataclass
class Dossier:
    """One subject, everything known, with the workings kept."""

    subject: str = ""
    input_query: str = ""
    generated_at: float = field(default_factory=time.time)

    full_name: EvidenceSet = field(default_factory=EvidenceSet)
    aliases: EvidenceSet = field(default_factory=lambda: EvidenceSet(multivalued=True))
    date_of_birth: EvidenceSet = field(default_factory=EvidenceSet)
    phones: EvidenceSet = field(default_factory=lambda: EvidenceSet(multivalued=True))

    education: list[EducationRecord] = field(default_factory=list)
    employment: list[EmploymentRecord] = field(default_factory=list)

    linked_accounts: list[socials.SocialAccount] = field(default_factory=list)
    exposure_records: list[dict[str, Any]] = field(default_factory=list)

    #: ``[(module, status, reason)]`` - what could not be looked at. Carried
    #: into the dossier because an empty section means "nothing found" and
    #: these are the sections where that reading would be wrong.
    collection_errors: list[tuple[str, str, str]] = field(default_factory=list)
    #: Other people the search matched, when the subject is ambiguous.
    candidates: list[dict[str, Any]] = field(default_factory=list)
    #: 0.0-1.0 that the dossier is about one person, from the brief resolution.
    subject_confidence: float | None = None
    subject_verdict: str = ""

    # -- reading -----------------------------------------------------------

    @property
    def synthetic(self) -> bool:
        """True when any value in here came from a fixture rather than the world."""
        for evidence_set in (self.full_name, self.aliases, self.date_of_birth,
                             self.phones):
            if any(e.synthetic for e in evidence_set):
                return True
        for record in (*self.education, *self.employment):
            if any(e.synthetic for e in record.evidence):
                return True
        return False

    @property
    def disputes(self) -> list[tuple[str, EvidenceSet]]:
        """Single-valued fields where sources disagree."""
        named = (("full_name", self.full_name), ("date_of_birth", self.date_of_birth))
        return [(name, s) for name, s in named if s.disputed]

    def to_dict(self) -> dict[str, Any]:
        """The nested shape the caller's spec asks for, plus the provenance.

        ``identity`` / ``background`` / ``digital_footprint`` / ``confidence``
        are exactly as specified. Everything a consumer of that shape does not
        know about is additive and sits alongside, so reading only those four
        keys works.
        """
        return {
            "identity": {
                "full_name": self.full_name.to_list(),
                "aliases": self.aliases.to_list(),
                "date_of_birth": self.date_of_birth.to_list(),
                "associated_phone_numbers": self.phones.to_list(),
            },
            "background": {
                "education": [r.to_dict() for r in self.education],
                "employment": [r.to_dict() for r in self.employment],
            },
            "digital_footprint": {
                "linked_accounts": [a.to_dict() for a in self.linked_accounts],
                "exposure_records": list(self.exposure_records),
            },
            # The spec's "confidence" block: the ranked evidence per field, so
            # a consumer can read scores without walking the identity tree.
            "confidence": {
                "identity": self.full_name.to_list(),
                "education": [{"school_name": r.school_name,
                               "confidence": round(r.confidence, 3),
                               "evidence": [e.to_dict() for e in r.evidence]}
                              for r in self.education],
                "employment": [{"company": r.company,
                                "confidence": round(r.confidence, 3),
                                "evidence": [e.to_dict() for e in r.evidence]}
                               for r in self.employment],
                "phones": self.phones.to_list(),
                "dob": self.date_of_birth.to_list(),
                "accounts": [{"value": a.url, "source": a.source or a.platform,
                              "confidence": _ACCOUNT_CONFIDENCE.get(a.basis, 0.4),
                              "evidence_type": "public_web_profile"}
                             for a in self.linked_accounts],
            },
            "meta": {
                "subject": self.subject,
                "input_query": self.input_query,
                "generated_at": self.generated_at,
                "subject_confidence": self.subject_confidence,
                "subject_verdict": self.subject_verdict,
                "synthetic": self.synthetic,
                "disputed_fields": [name for name, _ in self.disputes],
                "candidates": self.candidates,
                "collection_errors": [
                    {"module": m, "status": s, "reason": r}
                    for m, s, r in self.collection_errors],
            },
        }


#: How much a social account's basis is worth. ``search`` is a link to check by
#: hand, not a finding, so it scores as near-nothing rather than as a hit.
_ACCOUNT_CONFIDENCE = {"confirmed": 0.85, "declared": 0.70, "possible": 0.45,
                       "search": 0.10}

#: Relevance below which a graph entity more than one hop out is not treated as
#: the subject's own. The graph's scoring already demotes hubs and long chains;
#: this just declines to copy the tail of it into the identity section.
_ALIAS_FLOOR = 0.15


# ---------------------------------------------------------------------------
# the entry point
# ---------------------------------------------------------------------------


def generate_target_dossier(
    inv: Investigation,
    *,
    extra: TargetIdentifiers | None = None,
    exposure_text: str | None = None,
) -> Dossier:
    """Consolidate *inv* into one biographical dossier.

    This is a pure read over an investigation the engine already ran - it makes
    no network request of its own, so it can be re-run over a stored case, over
    a replayed one, or over a scan that finished an hour ago, and produce the
    same object.

    :param extra: identifiers the caller supplied directly. These enter at
        ``user_provided`` weight, because the user asserting their own subject
        is a premise of the investigation rather than one of its findings.
    :param exposure_text: a sanitised exposure record to fold in. Parsed by
        :func:`parse_exposure_metadata`, which cannot return credentials.
    """
    dossier = Dossier(input_query=inv.target,
                      generated_at=inv.finished_at or time.time())

    subjects = biography.extract(inv)
    primary = next((s for s in subjects if not s.candidate), None)
    if primary is None and subjects:
        primary = subjects[0]
    dossier.subject = primary.name if primary else inv.target

    # Other people the name matched. Kept rather than dropped, because "there
    # are three of them and I cannot separate them" is a real answer - but the
    # subject is never one of them. When every block is flagged as a candidate
    # the first one is promoted above, and listing it again below is the tool
    # agreeing with itself and calling it a second person.
    chosen = normalise(dossier.subject)
    dossier.candidates = [{"name": s.name} for s in subjects
                          if s.candidate and normalise(s.name) != chosen]

    if primary is not None:
        _fold_biography(dossier, primary)

    _fold_brief(dossier, inv)
    _fold_graph(dossier, inv)
    _fold_resolution(dossier, inv)

    if extra is not None:
        _fold_identifiers(dossier, extra)

    dossier.linked_accounts = socials.collect(inv)
    _fold_exposure(dossier, inv, exposure_text)
    _fold_gaps(dossier, inv)

    return dossier


# ---------------------------------------------------------------------------
# folding each existing source into the dossier
# ---------------------------------------------------------------------------

#: biography attribute label -> where it lands here.
_IDENTITY_LABELS = {
    "Name": "full_name",
    "Also known as": "aliases",
    "Date of birth": "date_of_birth",
}


def _fold_biography(dossier: Dossier, subject: biography.Subject) -> None:
    """Read the existing attribute extraction into the dossier's fields."""
    by_label = {a.label: a for a in subject.attributes}

    for label, target in _IDENTITY_LABELS.items():
        attribute = by_label.get(label)
        if not attribute:
            continue
        bucket: EvidenceSet = getattr(dossier, target)
        for value in attribute.values:
            # ``basis`` is the finding's own source, so a guessed name is
            # weighted as a guess rather than as whatever module made it.
            bucket.add(_evidence(value.text, value.basis, grade=value.grade,
                                 url=value.url))

    # The subject's own display name is a name, and it is often the only one.
    if subject.name and not dossier.full_name:
        dossier.full_name.add(_evidence(subject.name, "biography", grade="C3"))

    dossier.education = _education(by_label.get("Education"))
    dossier.employment = _employment(by_label.get("Employer"),
                                     by_label.get("Position held"),
                                     by_label.get("Occupation"))


_YEAR = re.compile(r"\b(18\d{2}|19\d{2}|20\d{2})\b")
#: "BSc Computer Science, MIT" / "MIT - PhD". Degrees are named in a small
#: enough vocabulary to match rather than guess.
_DEGREE = re.compile(
    r"\b(ph\.?d|doctorate|d\.?phil|m\.?sc|master'?s?|m\.?eng|m\.?b\.?a|m\.?a\b"
    r"|b\.?sc|bachelor'?s?|b\.?eng|b\.?a\b|associate'?s?|diploma|certificate)\b",
    re.I)
_DATE_RANGE = re.compile(
    r"\b((?:19|20)\d{2})\s*(?:-|--|—|–|to|until)\s*((?:19|20)\d{2}|present|current|now)\b",
    re.I)
#: Words that make a comma-separated fragment the *institution* rather than the
#: subject studied. "BSc Computer Science, Generic State University" splits into
#: a field and a school, and only one of them belongs in the School column.
_INSTITUTION = re.compile(
    r"\b(universit|college|school|institut|academy|polytechnic|conservato"
    r"|hochschule|universidad|université|universita|gymnasium|seminary)", re.I)


def _school_name(text: str) -> str:
    """The institution inside an education string, without the field of study.

    Picks the comma-separated fragment that names an institution. Falls back to
    the last fragment, which is where a school normally sits, and finally to the
    whole string - a school with an unusual name is better shown intact than
    truncated to a guess.
    """
    parts = [p.strip(" ,;()-–—\t") for p in text.split(",")]
    parts = [p for p in parts if p]
    if not parts:
        return text.strip()
    for part in parts:
        if _INSTITUTION.search(part):
            return part
    return parts[-1]


def _education(attribute: biography.Attribute | None) -> list[EducationRecord]:
    """Split each education value into school, year and degree.

    The year and the degree are pulled *out* of the string rather than guessed
    at, and the school name is what is left once they are removed. A value that
    carries neither still produces a record - a school with no graduation year
    is the normal case, not a failure.
    """
    if not attribute:
        return []
    records: list[EducationRecord] = []
    seen: dict[str, EducationRecord] = {}

    for value in attribute.values:
        text = value.text.strip()
        if not text:
            continue
        year = None
        if m := _YEAR.search(text):
            year = m.group(1)
        degree = None
        if m := _DEGREE.search(text):
            degree = m.group(1)

        school = _YEAR.sub("", text)
        if degree:
            school = _DEGREE.sub("", school)
        school = _school_name(school)
        if not school:
            school = text

        key = normalise(school)
        evidence = _evidence(text, value.basis, grade=value.grade, url=value.url)
        if key in seen:
            record = seen[key]
            record.graduation_year = record.graduation_year or year
            record.degree = record.degree or degree
            record.evidence.append(evidence)
            continue
        record = EducationRecord(school_name=school, graduation_year=year,
                                 degree=degree, evidence=[evidence])
        seen[key] = record
        records.append(record)

    records.sort(key=lambda r: -r.confidence)
    return records


def _employment(employer: biography.Attribute | None,
                position: biography.Attribute | None,
                occupation: biography.Attribute | None) -> list[EmploymentRecord]:
    """Build employment records, pairing a role to a company only when honest.

    The pairing rule, which is the whole point of this function:

    * a value that carries both ("Systems Administrator at Acme") is split and
      paired, because a source said so;
    * otherwise, if there is exactly one company and exactly one role, they are
      paired, because there is no other candidate pairing to be wrong about;
    * otherwise every company gets ``role=None`` and ``role_paired=False``, and
      the roles are reported separately.

    Zipping two lists of different things is the tempting third option and it
    manufactures facts. Three employers and two titles have six possible
    pairings and the zip silently asserts one of them.
    """
    if not employer:
        return []

    roles = [v.text.strip() for v in (position.values if position else [])]
    roles += [v.text.strip() for v in (occupation.values if occupation else [])]
    roles = [r for r in roles if r]

    records: list[EmploymentRecord] = []
    seen: dict[str, EmploymentRecord] = {}
    inline_paired = 0

    for value in employer.values:
        text = value.text.strip()
        if not text:
            continue

        role: str | None = None
        company = text
        # "Systems Administrator at Acme Global Solutions" - one source, both
        # halves, so the pairing is theirs and not ours.
        if m := re.search(r"^(.*?)\s+(?:at|@|,)\s+(.+)$", text):
            left, right = m.group(1).strip(), m.group(2).strip()
            if _DEGREE.search(left) is None and len(left.split()) <= 6:
                role, company = left, right
                inline_paired += 1

        start = end = None
        if m := _DATE_RANGE.search(text):
            start, end = m.group(1), m.group(2)
            company = _DATE_RANGE.sub("", company).strip(" ,;()-–—")

        company = company.strip(" ,;()-–—\t").strip()
        if not company:
            company = text

        key = normalise(company, corporate=True)
        evidence = _evidence(text, value.basis, grade=value.grade, url=value.url)
        if key in seen:
            record = seen[key]
            record.role = record.role or role
            record.start_date = record.start_date or start
            record.end_date = record.end_date or end
            record.evidence.append(evidence)
            continue
        record = EmploymentRecord(company=company, role=role, start_date=start,
                                  end_date=end, role_paired=role is not None,
                                  evidence=[evidence])
        seen[key] = record
        records.append(record)

    # The one-to-one case: nothing else it could mean.
    unpaired = [r for r in records if r.role is None]
    if len(unpaired) == 1 and len(set(roles)) == 1 and not inline_paired:
        unpaired[0].role = roles[0]
        unpaired[0].role_paired = True
    elif unpaired and roles:
        # Several of each: name the roles on every record but flag that no
        # source tied this role to this company.
        for record in unpaired:
            record.role = None
            record.role_paired = False

    records.sort(key=lambda r: -r.confidence)
    return records


def _fold_brief(dossier: Dossier, inv: Investigation) -> None:
    """Everything the user already asserted, at ``user_provided`` weight."""
    brief = getattr(inv, "brief", None)
    if brief is None:
        return
    for claim in getattr(brief, "claims", []) or []:
        kind = str(getattr(claim, "kind", "") or "").casefold()
        value = str(getattr(claim, "value", "") or "").strip()
        if not value:
            continue
        # An uncertain claim is the user hedging, and the dossier should hedge
        # with them rather than reporting a maybe as a premise.
        sure = getattr(claim, "sure", True)
        kind_type = "user_provided" if sure else "public_web_profile"
        note = "" if sure else "you marked this uncertain"

        if "name" in kind:
            dossier.full_name.add(_evidence(value, "you", evidence_type=kind_type,
                                            grade="B2", note=note))
        elif kind in ("dob", "born", "birth", "date_of_birth"):
            dossier.date_of_birth.add(_evidence(value, "you", evidence_type=kind_type,
                                                grade="B2", note=note))
        elif "phone" in kind:
            dossier.phones.add(_evidence(value, "you", evidence_type=kind_type,
                                         grade="B2", note=note))
        elif kind in ("handle", "username", "alias"):
            dossier.aliases.add(_evidence(value, "you", evidence_type=kind_type,
                                          grade="B2", note=note))


def _fold_graph(dossier: Dossier, inv: Investigation) -> None:
    """Phone numbers, handles and organisations the entity graph turned up."""
    graph = getattr(inv, "graph", None)
    if graph is None:
        return

    # ``of_type`` returns graph Nodes, whose ``sources`` is the set of modules
    # that touched the entity - which is exactly the provenance the evidence
    # model wants, so corroboration survives the hand-off.
    for etype, bucket in ((EntityType.PHONE, dossier.phones),
                          (EntityType.USERNAME, dossier.aliases)):
        for node in graph.of_type(etype):
            value = str(node.entity.value or "").strip()
            if not value:
                continue
            # A node the seed barely reaches is not this subject's alias. The
            # graph already computed that relevance; ignoring it is how every
            # handle in a forty-node graph becomes "also known as".
            if node.score < _ALIAS_FLOOR and node.depth > 1:
                continue
            for source in sorted(node.sources) or ["graph"]:
                bucket.add(_evidence(value, source, grade="C3"))


def _fold_resolution(dossier: Dossier, inv: Investigation) -> None:
    """Carry the brief resolution's verdict across as the subject confidence."""
    resolution = getattr(inv, "resolution", None)
    if resolution is None:
        return
    verdict = getattr(resolution, "verdict", None)
    dossier.subject_verdict = str(getattr(verdict, "value", verdict) or "")
    leader = getattr(resolution, "leader", None)
    score = getattr(leader, "probability", None) if leader is not None else None
    if isinstance(score, (int, float)):
        dossier.subject_confidence = round(float(score), 3)


def _fold_identifiers(dossier: Dossier, extra: TargetIdentifiers) -> None:
    """Caller-supplied identifiers, which outrank anything the tool inferred."""
    for name in extra.display_names:
        dossier.full_name.add(_evidence(name, "you", evidence_type="user_provided",
                                        grade="B2"))
    for handle in extra.usernames:
        dossier.aliases.add(_evidence(handle, "you", evidence_type="user_provided",
                                      grade="B2"))
    for phone in extra.phones:
        dossier.phones.add(_evidence(phone, "you", evidence_type="user_provided",
                                     grade="B2"))


def _fold_exposure(dossier: Dossier, inv: Investigation,
                   exposure_text: str | None) -> None:
    """Breach *context*, never breach contents.

    The HIBP findings already in the investigation are metadata by construction
    - HIBP does not serve credentials - so they are carried straight across.
    Free text supplied by the caller goes through the parser, which is the part
    that can refuse.
    """
    for result in inv.results:
        if getattr(result, "module", "") not in ("breaches", "pwned"):
            continue
        for finding in result.findings:
            value = str(finding.value)
            if "none recorded" in value or "not found" in value:
                continue
            dossier.exposure_records.append({
                "source_name": finding.label,
                "detail": value,
                "source": finding.source,
                "url": finding.url,
                "confidence": _ACCOUNT_CONFIDENCE.get("confirmed", 0.85),
                "evidence_type": evidence_type_for(finding.source),
            })

    if not exposure_text:
        return

    meta = parse_exposure_metadata(exposure_text)
    if not meta.fields and not meta.contained_credentials:
        return

    dossier.exposure_records.append({
        "source_name": meta.get("source_name") or "caller-supplied record",
        "record_category": meta.get("record_category"),
        "breach_date": meta.get("breach_date"),
        "email_domain": meta.get("email_domain"),
        "exposed_fields": sorted(meta.fields),
        "credential_fields_present": meta.credential_fields_present,
        "redacted_values": meta.redacted_values,
        "evidence_type": "public_web_profile",
    })

    # The biographical half of the record is what the dossier is actually for.
    source = f"exposure:{meta.get('source_name') or 'record'}"
    if dob := meta.get("date_of_birth"):
        dossier.date_of_birth.add(_evidence(dob, source, grade="D3",
                                            evidence_type="historical_forum"))
    for handle in meta.fields.get("username", []):
        dossier.aliases.add(_evidence(handle, source, grade="D3",
                                      evidence_type="historical_forum"))
    for phone in meta.fields.get("phone", []):
        dossier.phones.add(_evidence(phone, source, grade="D3",
                                     evidence_type="historical_forum"))
    for name in meta.fields.get("full_name", []):
        dossier.full_name.add(_evidence(name, source, grade="D3",
                                        evidence_type="historical_forum"))
    for company in meta.fields.get("employer", []):
        if not any(normalise(r.company, corporate=True) == normalise(company, corporate=True)
                   for r in dossier.employment):
            dossier.employment.append(EmploymentRecord(
                company=company, role=None, role_paired=False,
                evidence=[_evidence(company, source, grade="D3",
                                    evidence_type="historical_forum")]))
    for school in meta.fields.get("school", []):
        if not any(normalise(r.school_name) == normalise(school)
                   for r in dossier.education):
            dossier.education.append(EducationRecord(
                school_name=school,
                graduation_year=meta.get("graduation_year"),
                evidence=[_evidence(school, source, grade="D3",
                                    evidence_type="historical_forum")]))


def _fold_gaps(dossier: Dossier, inv: Investigation) -> None:
    """What could not be looked at, de-duplicated.

    De-duplication matters more here than anywhere else in the report: the same
    module failing the same way for five entities produced five identical rows,
    and a coverage table nobody reads is the same as no coverage table.
    """
    seen: set[tuple[str, str, str]] = set()
    rows: list[tuple[str, str, str]] = []

    for module, reason in getattr(inv, "skipped", []) or []:
        row = (str(module), "skipped", str(reason))
        if row not in seen:
            seen.add(row)
            rows.append(row)

    for result in inv.results:
        module = str(getattr(result, "module", "?"))
        for error in getattr(result, "errors", []) or []:
            row = (module, "partial", str(error))
            if row not in seen:
                seen.add(row)
                rows.append(row)
        # A module that was refused (rate limited, login wall) is a gap even
        # when it raised no error: "could not look" must never read as
        # "found nothing".
        reason = str(getattr(result, "status_reason", "") or "")
        status = getattr(result, "status", None)
        status_name = str(getattr(status, "value", status) or "")
        if reason and status_name not in ("ok", "complete", ""):
            row = (module, status_name, reason)
            if row not in seen:
                seen.add(row)
                rows.append(row)

    dossier.collection_errors = rows


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def render_json(dossier: Dossier, indent: int = 2) -> str:
    """The dossier as JSON, in the nested shape :meth:`Dossier.to_dict` builds."""
    import json

    return json.dumps(dossier.to_dict(), indent=indent, ensure_ascii=False,
                      sort_keys=False, default=str)


def render_markdown(dossier: Dossier) -> str:
    """The dossier as a readable report.

    Ordered the way the question is asked: who they are, what they have done,
    where they are online, then - and this is the part most tools leave out -
    what disagreed and what could not be checked. A dossier that ends on its
    findings invites the reader to treat the findings as the whole picture.
    """
    out: list[str] = []
    add = out.append

    add(f"# Dossier: {dossier.subject or dossier.input_query}")
    add("")
    add(f"- **Input query:** `{dossier.input_query}`")
    add(f"- **Generated:** {_stamp(dossier.generated_at)}")
    if dossier.subject_confidence is not None:
        add(f"- **Subject match confidence:** {dossier.subject_confidence:.0%}"
            f"{' - ' + dossier.subject_verdict if dossier.subject_verdict else ''}")
    elif dossier.subject_verdict:
        add(f"- **Subject match:** {dossier.subject_verdict}")
    add("")

    if dossier.synthetic:
        add("> **This dossier contains synthetic fixture data.** Values marked")
        add("> `synthetic` came from a local test fixture, not from the world.")
        add("> It is a development artefact and must not be read as findings.")
        add("")

    # -- identity ----------------------------------------------------------
    add("## Identity")
    add("")
    add(_field_table([
        ("Full name", dossier.full_name),
        ("Date of birth", dossier.date_of_birth),
        ("Aliases", dossier.aliases),
        ("Phone numbers", dossier.phones),
    ]))
    add("")

    if dossier.candidates:
        add("### Other people this matched")
        add("")
        add("The name search matched more than one person. Nothing below has")
        add("been merged into the subject above.")
        add("")
        for candidate in dossier.candidates:
            add(f"- {candidate.get('name', '?')}")
        add("")

    # -- background --------------------------------------------------------
    add("## Background")
    add("")
    add("### Education")
    add("")
    if dossier.education:
        add("| School | Graduated | Degree | Confidence | Source |")
        add("|---|---|---|---|---|")
        for record in dossier.education:
            sources = ", ".join(sorted({e.source for e in record.evidence}))
            add(f"| {_md(record.school_name)} | {record.graduation_year or '-'} "
                f"| {record.degree or '-'} | {record.confidence:.2f} | {_md(sources)} |")
    else:
        add("*Nothing established.*")
    add("")

    add("### Employment")
    add("")
    if dossier.employment:
        add("| Company | Role | From | To | Confidence | Source |")
        add("|---|---|---|---|---|---|")
        for record in dossier.employment:
            sources = ", ".join(sorted({e.source for e in record.evidence}))
            role = record.role or "-"
            if record.role and not record.role_paired:
                role = f"{record.role} *(not tied to this employer by any source)*"
            add(f"| {_md(record.company)} | {_md(role)} | {record.start_date or '-'} "
                f"| {record.end_date or '-'} | {record.confidence:.2f} | {_md(sources)} |")
        unpaired = [r for r in dossier.employment if not r.role_paired]
        if unpaired:
            add("")
            add("Roles found in this investigation were not tied to a specific")
            add("employer by any source, so they are not shown against one.")
    else:
        add("*Nothing established.*")
    add("")

    # -- digital footprint -------------------------------------------------
    add("## Digital footprint")
    add("")
    add("### Linked accounts")
    add("")
    if dossier.linked_accounts:
        add("| Platform | Handle | Link | Basis | Confidence |")
        add("|---|---|---|---|---|")
        for account in dossier.linked_accounts:
            score = _ACCOUNT_CONFIDENCE.get(account.basis, 0.4)
            handle = f"`{account.handle}`" if account.handle else ""
            add(f"| {_md(account.platform)} | {handle} | <{account.url}> "
                f"| {account.basis} | {score:.2f} |")
        add("")
        add("`confirmed` a lookup verified it &nbsp; `declared` a source said so"
            " &nbsp; `possible` name matches, owner unconfirmed &nbsp;"
            " `search` a link to check by hand, not a finding")
    else:
        add("*Nothing established.*")
    add("")

    add("### Exposure records")
    add("")
    add("Breach *context* only. This tool does not read, store or report")
    add("passwords, hashes, tokens, cookies or keys.")
    add("")
    if dossier.exposure_records:
        for record in dossier.exposure_records:
            name = record.get("source_name") or "record"
            add(f"- **{_md(str(name))}**"
                + (f" ({record['breach_date']})" if record.get("breach_date") else ""))
            if detail := record.get("detail"):
                add(f"  - {_md(str(detail))}")
            if fields := record.get("exposed_fields"):
                add(f"  - fields read: {', '.join(fields)}")
            if refused := record.get("credential_fields_present"):
                add(f"  - **credential fields present and not read:**"
                    f" {', '.join(sorted(set(refused)))}")
            if record.get("redacted_values"):
                add(f"  - {record['redacted_values']} value(s) redacted as"
                    f" credential-shaped")
    else:
        add("*Nothing established.*")
    add("")

    # -- the honest half ---------------------------------------------------
    disputes = dossier.disputes
    if disputes:
        add("## Conflicts")
        add("")
        add("Sources disagree about the following. Nothing has been chosen for")
        add("you; the values are ranked by the weight of their source.")
        add("")
        for name, evidence_set in disputes:
            add(f"**{name.replace('_', ' ')}**")
            add("")
            add("| Value | Source | Confidence | Kind |")
            add("|---|---|---|---|")
            for item in evidence_set:
                add(f"| {_md(item.value)} | {_md(item.source)} "
                    f"| {item.confidence:.2f} | {item.evidence_type} |")
            add("")

    add("## Collection gaps")
    add("")
    if dossier.collection_errors:
        add("Everything below either did not run or did not finish. Treat the")
        add("absence of findings from these sources as *unknown*, not *none*.")
        add("")
        add("| Module | Status | Reason |")
        add("|---|---|---|")
        for module, status, reason in dossier.collection_errors:
            add(f"| {_md(module)} | {status} | {_md(reason)} |")
    else:
        add("*Every source ran cleanly.*")
    add("")

    return "\n".join(out)


def _field_table(fields: list[tuple[str, EvidenceSet]]) -> str:
    """One table for the identity block, with every competing value kept."""
    rows = ["| Field | Value | Source | Confidence |", "|---|---|---|---|"]
    for label, evidence_set in fields:
        if not evidence_set:
            rows.append(f"| {label} | *not established* | - | - |")
            continue
        for index, item in enumerate(evidence_set):
            shown = label if index == 0 else ""
            sources = ", ".join(sorted(set(item.sources))) or item.source
            mark = " *(synthetic)*" if item.synthetic else ""
            rows.append(f"| {shown} | {_md(item.value)}{mark} | {_md(sources)} "
                        f"| {item.confidence:.2f} |")
    return "\n".join(rows)


def _stamp(epoch: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))


def _md(text: str) -> str:
    """Escape the characters that would break out of a Markdown table cell."""
    return str(text).replace("|", r"\|").replace("\n", " ").strip()
