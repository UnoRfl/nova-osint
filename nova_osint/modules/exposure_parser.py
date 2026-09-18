"""Reading breach-dump *metadata* without touching the credentials in it.

A sanitised exposure record is genuinely useful context: it can tell you an
address was in a 2019 incident alongside an employer string and a date of
birth, and those are biographical facts a dossier wants. The passwords and
hashes sitting next to them are not context, they are the thing that turns
OSINT into intrusion, and this module is built so that returning one is not an
oversight you can make - it is an operation that does not exist here.

How the refusal is structural rather than polite
------------------------------------------------

Two independent mechanisms, because a denylist alone fails the moment a dump
uses a field name nobody predicted:

1. **An allowlist of fields.** :data:`FIELD_PATTERNS` is the complete set of
   things this parser can emit. A field not named there is not extracted, so
   an unrecognised ``ntlm_hash:`` column is ignored by default rather than by
   having been anticipated.

2. **A value-shape guard.** Everything that survives the allowlist is still run
   past :func:`looks_like_secret` before it is returned, so a credential that
   arrives *inside* a permitted field - ``Employer: Acme / pw: hunter2`` - is
   dropped rather than laundered through a field name that looked innocent.

The denylist in :data:`CREDENTIAL_FIELDS` exists on top of those two, purely so
that the report can honestly say "this record contained credential fields,
which were not read" instead of silently showing a thinner record than the
input. Telling the analyst that a dump had passwords in it is useful; showing
them the passwords is not.

Nothing in this module performs any network request. It parses text the caller
already has and is authorised to process.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# what may be read
# ---------------------------------------------------------------------------

#: The complete set of fields this parser will return, as
#: ``name -> (pattern, multivalued)``. Adding an entry here is the only way to
#: widen what the parser can emit, which keeps the decision in one reviewable
#: place instead of spread across call sites.
#:
#: Each pattern captures the value in group 1 and is matched case-insensitively
#: against a single line.
FIELD_PATTERNS: dict[str, tuple[re.Pattern[str], bool]] = {
    "date_of_birth": (
        re.compile(r"^\s*(?:dob|d\.o\.b\.?|date[ _-]?of[ _-]?birth|birth[ _-]?date)"
                   r"\s*[:=]\s*(.+?)\s*$", re.I), False),
    "employer": (
        re.compile(r"^\s*(?:employer|company|organisation|organization|works[ _-]?at)"
                   r"\s*[:=]\s*(.+?)\s*$", re.I), True),
    "job_title": (
        re.compile(r"^\s*(?:job[ _-]?title|title|role|position|occupation)"
                   r"\s*[:=]\s*(.+?)\s*$", re.I), True),
    "school": (
        re.compile(r"^\s*(?:school|university|college|educated[ _-]?at|alma[ _-]?mater"
                   r"|institution)\s*[:=]\s*(.+?)\s*$", re.I), True),
    "graduation_year": (
        re.compile(r"^\s*(?:grad(?:uation)?[ _-]?year|class[ _-]?of)"
                   r"\s*[:=]\s*(.+?)\s*$", re.I), False),
    "username": (
        re.compile(r"^\s*(?:username|user[ _-]?name|handle|nick(?:name)?|login|screen[ _-]?name)"
                   r"\s*[:=]\s*(.+?)\s*$", re.I), True),
    "full_name": (
        re.compile(r"^\s*(?:name|full[ _-]?name|real[ _-]?name)\s*[:=]\s*(.+?)\s*$", re.I),
        True),
    "email_domain": (
        re.compile(r"^\s*(?:email|e-?mail|address)\s*[:=]\s*(.+?)\s*$", re.I), True),
    "phone": (
        re.compile(r"^\s*(?:phone|mobile|tel(?:ephone)?|msisdn)\s*[:=]\s*(.+?)\s*$", re.I),
        True),
    "source_name": (
        re.compile(r"^\s*(?:source|breach|dump|database|db)\s*[:=]\s*(.+?)\s*$", re.I),
        False),
    "breach_date": (
        re.compile(r"^\s*(?:breach[ _-]?date|date|leaked[ _-]?on|compromised[ _-]?on)"
                   r"\s*[:=]\s*(.+?)\s*$", re.I), False),
    "record_category": (
        re.compile(r"^\s*(?:category|type|record[ _-]?type|classification)"
                   r"\s*[:=]\s*(.+?)\s*$", re.I), False),
}

#: Field names whose *presence* is reported and whose value is never read.
#:
#: This is not the security control - the allowlist above is - but naming what
#: was refused is what stops a sanitised record from looking like a complete
#: one. An analyst who knows the dump had a password column can reason about
#: what else it might contain.
CREDENTIAL_FIELDS = re.compile(
    r"^\s*(pass(?:word|wd|_hash)?|pwd|hash|md5|sha1|sha256|sha512|bcrypt|scrypt"
    r"|argon2|ntlm|lm[ _-]?hash|salt|secret|token|api[ _-]?key|apikey|access[ _-]?token"
    r"|refresh[ _-]?token|session|cookie|auth|bearer|private[ _-]?key|seed[ _-]?phrase"
    r"|mnemonic|otp|totp|mfa|security[ _-]?(?:question|answer)|pin|cvv|cvc"
    r"|card[ _-]?number|iban|ssn|credit[ _-]?card)\s*[:=]", re.I)

# ---------------------------------------------------------------------------
# what a secret looks like, regardless of what it was called
# ---------------------------------------------------------------------------

#: Shapes that are credentials whatever field they turned up in. Matched
#: against the *value*, so a password hiding in an "employer" column is caught.
#:
#: Written as shapes rather than words on purpose: a check that keys off the
#: word "password" fails on a bare bcrypt string and passes on the sentence
#: "password policy", which is exactly backwards.
_SECRET_SHAPES: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\$(?:1|2[abxy]?|5|6|y|argon2[id]{1,2})\$"),   # crypt(3) / argon2
    re.compile(r"^[a-f0-9]{32}$", re.I),                        # md5
    re.compile(r"^[a-f0-9]{40}$", re.I),                        # sha1
    re.compile(r"^[a-f0-9]{64}$", re.I),                        # sha256
    re.compile(r"^[a-f0-9]{128}$", re.I),                       # sha512
    re.compile(r"^[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$"),  # JWT
    re.compile(r"^(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}$"),  # GitHub token
    re.compile(r"^(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}$"),  # Stripe-style
    re.compile(r"^AKIA[0-9A-Z]{16}$"),                          # AWS access key id
    re.compile(r"^xox[abposr]-[A-Za-z0-9-]{10,}$"),             # Slack token
    re.compile(r"^-----BEGIN [A-Z ]*PRIVATE KEY-----"),         # PEM private key
    re.compile(r"^sb_secret_[A-Za-z0-9_-]{8,}$"),               # Supabase secret
)

#: A run of high-entropy characters long enough that it is a key and not a
#: company name. Deliberately conservative: real employer and school strings
#: contain spaces, and this only fires on an unbroken token.
_LONG_OPAQUE = re.compile(r"^[A-Za-z0-9+/=_-]{40,}$")


def looks_like_secret(value: str) -> bool:
    """True when *value* has the shape of a credential and must not be returned.

    Shape-based rather than name-based, for the same reason the secret-shape CI
    guard is: a check that fires on the word "password" fails on the hash and
    trips over prose that merely discusses passwords.
    """
    text = str(value).strip()
    if not text:
        return False
    if any(p.search(text) for p in _SECRET_SHAPES):
        return True
    return bool(_LONG_OPAQUE.match(text))


# ---------------------------------------------------------------------------
# normalisation of the fields that are allowed through
# ---------------------------------------------------------------------------

_ISO_DATE = re.compile(r"\b(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})\b")
_DMY_DATE = re.compile(r"\b(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})\b")
_YEAR = re.compile(r"\b(18\d{2}|19\d{2}|20\d{2})\b")
_EMAIL = re.compile(r"[^@\s]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_PLACEHOLDER = frozenset({
    "", "-", "--", "n/a", "na", "null", "none", "nil", "unknown", "redacted",
    "[redacted]", "***", "xxx", "not set", "undisclosed", "<none>",
})


def _iso_date(text: str) -> str | None:
    """Normalise a date to ``YYYY-MM-DD``, or ``None`` if it is not one.

    Ambiguous ``03/04/2001`` is read day-first only when the first number
    cannot be a month, because guessing a locale silently is how a date of
    birth ends up two months wrong in a report that looks confident.
    """
    if m := _ISO_DATE.search(text):
        year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
    elif m := _DMY_DATE.search(text):
        day, month, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if month > 12:                      # clearly month-first after all
            day, month = month, day
    else:
        return None
    if not (1 <= month <= 12 and 1 <= day <= 31):
        return None
    return f"{year:04d}-{month:02d}-{day:02d}"


def _clean(value: str) -> str:
    """Trim quoting and trailing separators left by CSV-ish dumps."""
    return str(value).strip().strip("\"'").strip().rstrip(",;").strip()


@dataclass
class ExposureMetadata:
    """The non-sensitive half of an exposure record.

    ``credential_fields_present`` is the honest part: it names the columns that
    were refused, so a reader can tell a record that had no password from one
    whose password was not read.
    """

    fields: dict[str, list[str]] = field(default_factory=dict)
    credential_fields_present: list[str] = field(default_factory=list)
    #: Values dropped by :func:`looks_like_secret` after passing the allowlist.
    redacted_values: int = 0
    lines_read: int = 0

    @property
    def contained_credentials(self) -> bool:
        return bool(self.credential_fields_present) or self.redacted_values > 0

    def get(self, name: str) -> str | None:
        values = self.fields.get(name) or []
        return values[0] if values else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "fields": {k: list(v) for k, v in sorted(self.fields.items())},
            "credential_fields_present": sorted(set(self.credential_fields_present)),
            "redacted_values": self.redacted_values,
            "contained_credentials": self.contained_credentials,
            "lines_read": self.lines_read,
        }


def parse_exposure_metadata(raw_text: str) -> ExposureMetadata:
    """Extract only the non-sensitive metadata from an exposure record.

    Returns an :class:`ExposureMetadata` whose ``fields`` contains nothing but
    the keys named in :data:`FIELD_PATTERNS`, with every value having survived
    :func:`looks_like_secret`. Passwords, hashes, tokens, cookies, keys and
    session material are never returned, in any field, under any name.

    The parser is total: malformed input produces an empty result rather than
    an exception, because this runs inside a scan and one bad fixture must not
    take the investigation down with it.
    """
    meta = ExposureMetadata()
    if not raw_text:
        return meta

    for line in str(raw_text).splitlines():
        if not line.strip():
            continue
        meta.lines_read += 1

        # A credential column is noted and then abandoned - the value is never
        # even bound to a name, so there is nothing to accidentally return.
        if m := CREDENTIAL_FIELDS.match(line):
            meta.credential_fields_present.append(m.group(1).strip().lower())
            continue

        for name, (pattern, multivalued) in FIELD_PATTERNS.items():
            match = pattern.match(line)
            if not match:
                continue
            value = _clean(match.group(1))
            if not value or value.casefold() in _PLACEHOLDER:
                break
            # Second gate: the field was permitted, the value still might not be.
            if looks_like_secret(value):
                meta.redacted_values += 1
                break
            value = _normalise_field(name, value)
            if value is None:
                break
            bucket = meta.fields.setdefault(name, [])
            if value not in bucket and (multivalued or not bucket):
                bucket.append(value)
            break                            # one field per line

    return meta


def _normalise_field(name: str, value: str) -> str | None:
    """Field-specific normalisation, or ``None`` to drop the value.

    An email is reduced to its **domain** on purpose. The address itself is
    usually already the thing being investigated, and a dump's other addresses
    belong to other people who are not the subject of this report.
    """
    if name == "date_of_birth":
        return _iso_date(value)
    if name == "breach_date":
        # A breach is often dated to the year only, and a year is still useful.
        if iso := _iso_date(value):
            return iso
        m = _YEAR.search(value)
        return m.group(1) if m else None
    if name == "graduation_year":
        m = _YEAR.search(value)
        return m.group(1) if m else None
    if name == "email_domain":
        m = _EMAIL.search(value)
        return m.group(1).lower() if m else None
    if name == "phone":
        digits = re.sub(r"[^\d+]", "", value)
        return digits if len(re.sub(r"\D", "", digits)) >= 7 else None
    return value
