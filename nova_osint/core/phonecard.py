"""The phone answer card: one number in, one card out.

Modelled on what a caller-ID app is actually *for*. You have a number, you want
one screen that says what it is and whether to worry, not twelve rows of
parser output. So this collapses the phone module's findings into a verdict, a
risk line, and a short table.

What this cannot be, and says so
--------------------------------

A caller-ID app's headline trick - turning a number into a person's name - runs
on a database built by uploading millions of people's address books. That data
is proprietary, was collected from people who never agreed to be in it, and
there is no free API for it. NOVA does not have it, cannot derive it, and will
not scrape a service that does.

So the card is explicit about the boundary: it reports what the number *is*
(allocation, line type, carrier, geography, risk) and states plainly that the
subscriber's name is not something it can know. A tool that quietly omits that
distinction lets a reader assume the absence of a name means the number is
unlisted, rather than that the tool never had a way to look.

What it can do that a caller-ID app cannot
------------------------------------------

Search **your own** case history. If this number turned up in an earlier
investigation, the card says which case and what it sat next to. That is the
same mechanic - a contact book built from what has been seen - except the
corpus is the operator's own lawful collection rather than a stranger's stolen
address book.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import Investigation

# ---------------------------------------------------------------------------
# risk
# ---------------------------------------------------------------------------

#: ``line type -> (risk, what it means for the person holding the number)``.
#: These are statements about the *number*, never about its owner: a VoIP line
#: is disposable, which is a fact about the line, and says nothing about whether
#: whoever answers it is honest.
LINE_RISK: dict[str, tuple[str, str]] = {
    "premium rate": ("high", "calling this number charges you at a premium rate"),
    "VoIP": ("medium", "VoIP: cheap to obtain and discard, so it is a weak "
                       "identity signal - common for both privacy and fraud"),
    "personal number": ("medium", "a follow-me number that forwards elsewhere; "
                                  "the geography above is the routing, not the person"),
    "pager": ("low", "a pager, which is unusual enough to be worth noting"),
    "voicemail": ("medium", "a voicemail-only service, not a reachable line"),
    "toll free": ("low", "a toll-free business line, not a personal number"),
    "shared cost": ("low", "a shared-cost business line"),
    "UAN": ("low", "a universal access number - an organisation, not a person"),
    "mobile": ("low", "an allocated mobile number"),
    "fixed line": ("low", "an allocated landline, tied to a geographic area"),
    "fixed line or mobile": ("low", "allocated; the range covers both mobile and "
                                    "fixed lines so the type is ambiguous"),
}

RISK_ORDER = {"high": 3, "medium": 2, "low": 1, "unknown": 0}


@dataclass
class PhoneCard:
    number: str
    valid: bool = False
    verdict: str = ""
    region: str = ""
    country: str = ""
    carrier: str = ""
    line_type: str = "unknown"
    timezones: list[str] = field(default_factory=list)
    formats: dict[str, str] = field(default_factory=dict)
    risk: str = "unknown"
    risk_notes: list[str] = field(default_factory=list)
    #: ``(case id, when, target, context)`` for earlier sightings.
    seen_before: list[tuple[str, str, str, str]] = field(default_factory=list)
    links: list[tuple[str, str]] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    library: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "number": self.number, "valid": self.valid, "verdict": self.verdict,
            "country": self.country, "region": self.region, "carrier": self.carrier,
            "line_type": self.line_type, "timezones": self.timezones,
            "formats": self.formats, "risk": self.risk, "risk_notes": self.risk_notes,
            "seen_before": [{"case": c, "when": w, "target": t, "context": x}
                            for c, w, t, x in self.seen_before],
            "manual_checks": dict(self.links),
            "coverage_gaps": self.gaps,
            "subscriber_name": None,
            "subscriber_name_note": NAME_NOTE,
        }


NAME_NOTE = (
    "NOVA cannot tell you the subscriber's name. Caller-ID apps do that from a "
    "database built by harvesting people's address books; it is proprietary, "
    "collected without the consent of the people in it, and NOVA neither holds "
    "it nor scrapes anyone who does. Absence of a name here means the tool had "
    "no lawful way to look - not that the number is unlisted."
)


# ---------------------------------------------------------------------------
# building
# ---------------------------------------------------------------------------


def build(inv: Investigation, store: Any = None) -> PhoneCard:
    """Collapse a phone scan into one card, optionally enriched from the store."""
    from .report import status_rows

    card = PhoneCard(number=inv.target)
    values: dict[str, Any] = {}
    for result in inv.results:
        for finding in result.findings:
            values.setdefault(finding.label, finding.value)
            if finding.source == "link" and finding.label.startswith("check manually: "):
                card.links.append((finding.label.removeprefix("check manually: "),
                                   str(finding.value)))
    card.gaps = [f"{m}: {s}" + (f" - {r}" if r else "") for m, s, r in status_rows(inv)]
    card.library = "library" not in values

    card.valid = str(values.get("valid", "")).startswith("yes")
    card.region = str(values.get("region", "") or "")
    card.country = str(values.get("country code", "") or "")
    card.carrier = str(values.get("carrier at allocation", "") or "")
    card.line_type = str(values.get("line type", "unknown") or "unknown")
    tz = values.get("timezone(s)")
    card.timezones = list(tz) if isinstance(tz, (list, tuple)) else ([tz] if tz else [])
    for key, label in (("E.164", "E.164"), ("international", "international")):
        if values.get(key):
            card.formats[label] = str(values[key])

    card.risk, card.risk_notes = _assess(card)
    card.verdict = _verdict(card)
    if store is not None:
        card.seen_before = _seen_before(card, store)
    return card


def _assess(card: PhoneCard) -> tuple[str, list[str]]:
    notes: list[str] = []
    risk, note = LINE_RISK.get(card.line_type, ("unknown", ""))
    if note:
        notes.append(note)

    if not card.valid:
        # The strongest signal the offline data can give. A number outside the
        # allocated ranges cannot be dialled, so a call or message that appeared
        # to come from it had its caller ID forged.
        risk = "high"
        notes.insert(0, "this is not an allocated number - anything that appeared "
                        "to call or text you from it was spoofing the caller ID")
    if not card.library:
        notes.append("phonenumbers is not installed, so line type, carrier and "
                     "region could not be determined (pip install phonenumbers)")
        risk = "unknown"
    return risk, notes


def _verdict(card: PhoneCard) -> str:
    """The one line somebody reads before anything else."""
    if not card.library:
        return "unparsed - install phonenumbers for a real answer"
    if not card.valid:
        return "NOT A REAL NUMBER - not in any allocated range"
    bits = [card.line_type]
    if card.carrier:
        bits.append(card.carrier)
    if card.region:
        bits.append(card.region)
    elif card.country:
        bits.append(card.country)
    return " / ".join(b for b in bits if b)


def _seen_before(card: PhoneCard, store: Any) -> list[tuple[str, str, str, str]]:
    """Every earlier case that recorded this number.

    The honest version of a caller-ID lookup: a contact book built from the
    operator's own collection rather than from strangers' address books.
    """
    from .entities import Entity, EntityType

    candidates = {card.formats.get("E.164", ""), card.number}
    out: list[tuple[str, str, str, str]] = []
    seen_cases: set[str] = set()
    for raw in filter(None, candidates):
        entity = Entity.make(EntityType.PHONE, raw)
        if entity is None:
            continue
        try:
            cases = store.seen_elsewhere(entity)
        except Exception:  # noqa: BLE001 - a store problem must not kill the card
            return out
        for case in cases:
            if case.id in seen_cases:
                continue
            seen_cases.add(case.id)
            context = ""
            try:
                graph = store.graph(case.id)
                peers = sorted(graph.neighbors(entity.eid))[:3]
                context = ", ".join(p.split(":", 1)[-1] for p in peers)
            except Exception:  # noqa: BLE001
                pass
            out.append((case.id, case.when, case.target, context))
    return sorted(out, key=lambda row: row[1], reverse=True)


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

RISK_MARK = {"high": "!!", "medium": " !", "low": "  ", "unknown": " ?"}
WIDTH = 68


def render_text(card: PhoneCard) -> str:
    def line(text: str = "") -> str:
        return "  " + text

    out = ["", "  " + "─" * WIDTH]
    out.append(line(f"  {card.formats.get('international', card.number)}"))
    out.append(line(f"  {card.verdict}"))
    out.append("  " + "─" * WIDTH)
    out.append("")

    rows = [
        ("line", card.line_type),
        ("carrier", card.carrier + (" (at allocation)" if card.carrier else "")),
        ("region", card.region),
        ("country", card.country),
        ("timezone", ", ".join(card.timezones)),
        ("E.164", card.formats.get("E.164", "")),
        ("allocated", "yes" if card.valid else "NO"),
    ]
    for label, value in rows:
        if value:
            out.append(line(f"  {label.upper():<10} {value}"))

    out.append("")
    out.append(line(f"  RISK       {RISK_MARK[card.risk]} {card.risk.upper()}"))
    for note in card.risk_notes:
        for chunk in _wrap(note, WIDTH - 14):
            out.append(line(f"             {chunk}"))

    out.append("")
    if card.seen_before:
        out.append(line("  SEEN BEFORE  in your own cases"))
        for case, when, target, context in card.seen_before:
            out.append(line(f"    {when}  {case}  while scanning {target}"))
            if context:
                out.append(line(f"      alongside: {context}"))
    else:
        out.append(line("  SEEN BEFORE  never, in any saved case"))

    out.append("")
    out.append(line("  NOT KNOWN"))
    for chunk in _wrap(NAME_NOTE, WIDTH - 6):
        out.append(line(f"    {chunk}"))

    if card.links:
        out.append("")
        out.append(line("  CHECK BY HAND"))
        for label, url in card.links:
            out.append(line(f"    {label:<16} {url}"))

    if card.gaps:
        out.append("")
        out.append(line("  COVERAGE GAPS"))
        for gap in card.gaps:
            out.append(line(f"    {gap}"))

    out.append("  " + "─" * WIDTH)
    out.append("")
    return "\n".join(out)


def _wrap(text: str, width: int) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines


def render_json(card: PhoneCard) -> str:
    import json

    return json.dumps(card.to_dict(), indent=2, default=str)
