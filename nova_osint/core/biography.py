"""Biographical attributes, ordered by how much they matter.

A person profile should open the way a dossier opens - name, date of birth,
nationality, where they are - and work outward to the weaker material. The
entity sections cannot do that: they group by *kind of thing*, so a date of
birth and a favicon hash sit at the same level of prominence, which is nobody's
idea of a profile.

So this pulls the biographical facts out of the findings, whichever module
produced them, and lays them out in a fixed order of importance.

Two rules it will not bend
--------------------------

**Conflicts are shown, never resolved.** If Wikidata says 1974 and a profile
page says 1975, both appear with their sources. Picking one would be inventing
a fact, and the disagreement is itself the most interesting thing on the line.

**The core four are printed even when empty.** Name, date of birth, nationality
and location always appear, as ``not established`` when nothing was found.
Omitting an empty row lets a reader skim past it and assume it was never
relevant, when what actually happened is that nobody could find it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .models import Confidence, Investigation

# ---------------------------------------------------------------------------
# the attribute table
# ---------------------------------------------------------------------------

#: ``(label, pattern, always_show, note)`` in descending order of importance.
#:
#: The pattern is matched against a finding's label, so one entry catches the
#: same fact however it was phrased by whichever module found it - Wikidata
#: writes "Ada Lovelace: date of birth", GitHub writes "stated location".
ATTRIBUTES: list[tuple[str, re.Pattern[str], bool, str]] = [
    ("Name", re.compile(r"(^|: )(display name|full name|birth name|real name"
                        r"|possible real name)$", re.I), True, ""),
    ("Also known as", re.compile(r"(^|: )(also known as|alias|aka|other names"
                                 r"|nickname)$", re.I), False, ""),
    ("Date of birth", re.compile(r"(^|: )date of birth$", re.I), True, ""),
    ("Date of death", re.compile(r"(^|: )date of death$", re.I), False, ""),
    ("Nationality", re.compile(r"(^|: )(citizenship|nationality)$", re.I), True, ""),
    ("Gender", re.compile(r"(^|: )(gender|sex or gender)$", re.I), False, ""),
    ("Place of birth", re.compile(r"(^|: )(place of birth|birthplace)$", re.I),
     False, ""),
    ("Based in", re.compile(r"(^|: )(stated location|location|residence"
                            r"|headquarters|work location)$", re.I), True,
     "self-reported unless the source says otherwise"),
    ("Likely timezone", re.compile(r"(^|: )(timezone|inferred timezone"
                                   r"|timezone\(s\)|commit timezone)", re.I), False,
     "inferred from activity times, not stated"),
    ("Languages", re.compile(r"(^|: )(languages?|language spoken)", re.I), False, ""),
    ("Occupation", re.compile(r"(^|: )(occupation|job title|role)$", re.I), False, ""),
    ("Employer", re.compile(r"(^|: )(employer|company|works at)$", re.I), False, ""),
    ("Position held", re.compile(r"(^|: )(position held|chief executive|director"
                                 r"|board member)$", re.I), False, ""),
    ("Education", re.compile(r"(^|: )(educated at|education|alma mater)$", re.I),
     False, ""),
    ("Organisations", re.compile(r"(^|: )(organisations?|member of)$", re.I), False, ""),
    ("Bio", re.compile(r"(^|: )(bio|description|about)$", re.I), False, ""),
]

#: Values that are a placeholder rather than an answer. A module that reports
#: "unknown" is saying it looked and failed, which belongs in the gap column and
#: not on the line as though it were the person's nationality.
_EMPTY = frozenset({"", "-", "none", "n/a", "na", "null", "unknown", "not set",
                    "not stated", "undisclosed"})

_GRADE_FOR = {Confidence.CONFIRMED: "B2", Confidence.LIKELY: "C3",
              Confidence.POSSIBLE: "D3"}


@dataclass
class Value:
    text: str
    source: str
    grade: str
    url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"value": self.text, "source": self.source, "grade": self.grade,
                "url": self.url}


@dataclass
class Subject:
    """One person the biography could be about, and what is known of them.

    Plural on purpose. A name search that matched four people has four of these,
    and merging them produces a person who does not exist - the first version of
    this file cheerfully reported a subject born in both 1973 and 1974, working
    as an entrepreneur and a professional wrestler, educated at three
    universities. Every one of those facts was true of somebody; none of them
    were true of one body.
    """

    name: str
    attributes: list[Attribute] = field(default_factory=list)
    #: Set when this block is one candidate among several.
    candidate: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "candidate": self.candidate,
                "attributes": [a.to_dict() for a in self.attributes]}


@dataclass
class Attribute:
    label: str
    values: list[Value] = field(default_factory=list)
    note: str = ""

    @property
    def established(self) -> bool:
        return bool(self.values)

    @property
    def multivalued(self) -> bool:
        return len({v.text.casefold() for v in self.values}) > 1

    @property
    def disputed(self) -> bool:
        """Different *sources* giving different answers - a real contradiction.

        Three degrees from one encyclopaedia is a multi-valued fact, not a
        disagreement, and labelling it one cries wolf on the flag that is
        supposed to mean "somebody here is wrong".
        """
        return self.multivalued and len({v.source for v in self.values}) > 1

    def to_dict(self) -> dict[str, Any]:
        return {"label": self.label, "established": self.established,
                "disputed": self.disputed, "multivalued": self.multivalued,
                "note": self.note,
                "values": [v.to_dict() for v in self.values]}


# ---------------------------------------------------------------------------
# extraction
# ---------------------------------------------------------------------------


def extract(inv: Investigation) -> list[Subject]:
    """Biographical attributes, one block per person, most important first.

    Returns ``[]`` for a target that is not a person: a domain does not have a
    date of birth, and printing "Nationality: not established" for one would be
    noise pretending to be rigour.

    Findings are split by **who they are about**. Sources that resolve a name to
    several people prefix each fact with the person it belongs to
    ("Matt Prince: occupation"), and that prefix is the only thing keeping two
    strangers from being welded into one profile.
    """
    if inv.target_type.value not in ("person", "username", "email"):
        return []

    per_person: dict[str, dict[str, list[Value]]] = {}
    #: Which module named each candidate. Needed because a candidate's own name
    #: is filled in below from the heading, and attributing that to a fixed
    #: source would put a real module's name against a fact it never reported.
    named_by: dict[str, list[str]] = {}
    for result in inv.results:
        for finding in result.findings:
            label = str(finding.label)
            who, _, rest = label.partition(": ")
            if not rest:
                # No prefix: the fact is about whoever was scanned.
                who, rest = "", label
            elif result.module not in named_by.setdefault(who, []):
                named_by[who].append(result.module)
            for name, pattern, _always, _note in ATTRIBUTES:
                if not pattern.search(rest):
                    continue
                bucket = per_person.setdefault(who, {})
                for text in _texts(finding.value):
                    bucket.setdefault(name, []).append(Value(
                        text=text, source=result.module,
                        grade=_GRADE_FOR.get(finding.confidence, "D3"),
                        url=finding.url))
                break

    named = sorted(k for k in per_person if k)
    unprefixed = per_person.get("", {})

    if not named:
        # One subject, whatever was scanned. The ordinary username case.
        return [Subject(name=inv.target,
                        attributes=_attributes(unprefixed, core=True,
                                               known_name=None))]

    # Several candidates. Facts with no prefix came from scanning the seed and
    # belong to none of them in particular, so they are folded into each block
    # rather than silently assigned to the first.
    subjects = []
    for who in named:
        merged = {k: list(v) for k, v in unprefixed.items()}
        for key, values in per_person[who].items():
            merged.setdefault(key, []).extend(values)
        subjects.append(Subject(name=who, candidate=True,
                                attributes=_attributes(merged, core=True,
                                                       known_name=who,
                                                       named_by=named_by.get(who, []))))
    return subjects


def _attributes(found: dict[str, list[Value]], *, core: bool,
                known_name: str | None,
                named_by: list[str] | None = None) -> list[Attribute]:
    out = []
    for name, _pattern, always, note in ATTRIBUTES:
        values = _dedupe(found.get(name, []))
        if name == "Name" and known_name and not values:
            # The source that resolved this candidate named them. Printing
            # "Name: not established" directly under a heading carrying that
            # very name is the kind of thing that makes a reader distrust the
            # rest of the document.
            #
            # The source is whichever module prefixed its findings with this
            # name, not a fixed one: this used to say "wikidata" whoever had
            # actually reported it, which is a citation to a source that never
            # made the claim - the exact failure the grades exist to prevent.
            values = [Value(known_name, ", ".join(named_by or []) or "scan", "B2")]
        if values or (always and core):
            out.append(Attribute(label=name, values=values, note=note))
    return out


def _texts(value: Any) -> list[str]:
    items = value if isinstance(value, (list, tuple, set)) else [value]
    out = []
    for item in items:
        text = str(item).strip()
        if text.casefold() in _EMPTY or len(text) > 200:
            continue
        out.append(text)
    return out[:6]


def _dedupe(values: list[Value]) -> list[Value]:
    """One row per distinct answer, keeping every source that gave it.

    Two modules agreeing is corroboration and must not read as two facts, but
    two modules *disagreeing* must stay visible as two rows.
    """
    by_text: dict[str, Value] = {}
    # Sources are compared as whole names, not as substrings of the joined
    # string: "ip" is a substring of "abuseipdb", so a substring test drops the
    # second source and the line claims one witness where there were two.
    sources: dict[str, list[str]] = {}
    for value in values:
        key = value.text.casefold()
        if key in by_text:
            if value.source not in sources[key]:
                sources[key].append(value.source)
                by_text[key].source = ", ".join(sources[key])
            continue
        by_text[key] = Value(value.text, value.source, value.grade, value.url)
        sources[key] = [value.source]
    return list(by_text.values())


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def render_text(subjects: list[Subject], width: int = 16) -> str:
    if not subjects:
        return ""
    out = []
    for subject in subjects:
        if subject.candidate:
            out.append(f"\n  -- if this is {subject.name} --")
        out.append(_attributes_text(subject.attributes, width))
    return "\n".join(out)


def _attributes_text(attributes: list[Attribute], width: int) -> str:
    out: list[str] = []
    for attr in attributes:
        label = (attr.label + ":").ljust(width)
        if not attr.established:
            out.append(f"    {label} not established")
            continue
        first, *rest = attr.values
        flag = ("  (sources disagree)" if attr.disputed
                else "  (several)" if attr.multivalued else "")
        out.append(f"    {label} {first.text}"
                   f"   [{first.grade} {first.source}]{flag}")
        for value in rest:
            out.append(f"    {' ' * width} {value.text}"
                       f"   [{value.grade} {value.source}]")
        if attr.note:
            out.append(f"    {' ' * width} ({attr.note})")
    return "\n".join(out)


def render_markdown(subjects: list[Subject]) -> str:
    """The same block as the terminal, as a table.

    The markdown report used to have none of this: it went straight from the
    summary counts into one section per module, so a person scan exported to
    a file lost the entire "who is this" layer that the terminal and the HTML
    both lead with. A reader got twelve module headings and no answer.
    """
    if not subjects:
        return ""
    out: list[str] = []
    for subject in subjects:
        if subject.candidate:
            out += [f"**If this is {subject.name}**", ""]
        out += ["| Attribute | Value | Source |", "|---|---|---|"]
        for attr in subject.attributes:
            if not attr.established:
                out.append(f"| {attr.label} | *not established* | - |")
                continue
            first, *rest = attr.values
            flag = (" **(sources disagree)**" if attr.disputed
                    else " *(several)*" if attr.multivalued else "")
            out.append(f"| {attr.label} | {_md(first.text)}{flag} "
                       f"| `{first.grade}` {first.source} |")
            for value in rest:
                out.append(f"| | {_md(value.text)} | `{value.grade}` {value.source} |")
            if attr.note:
                out.append(f"| | *{attr.note}* | |")
        out.append("")
    return "\n".join(out)


def _md(text: str) -> str:
    """A cell value that cannot break out of its table row."""
    return text.replace("|", "\\|").replace("\n", " ")


def render_html(subjects: list[Subject]) -> str:
    import html as html_mod

    if not subjects:
        return ""
    e = html_mod.escape
    blocks = []
    for subject in subjects:
        head = (f"<p class='candhead'>if this is <b>{e(subject.name)}</b></p>"
                if subject.candidate else "")
        blocks.append(head + _attributes_html(subject.attributes))
    return "".join(blocks)


def _attributes_html(attributes: list[Attribute]) -> str:
    import html as html_mod

    e = html_mod.escape
    rows = []
    for attr in attributes:
        if not attr.established:
            rows.append(f"<tr><th class='k'>{e(attr.label)}</th>"
                        "<td class='dim'>not established</td></tr>")
            continue
        cells = []
        for value in attr.values:
            link = (f"<a href='{e(value.url)}' rel='noreferrer noopener'>"
                    f"{e(value.text)}</a>" if value.url else e(value.text))
            cells.append(f"{link} <span class='dim'>[{e(value.grade)} "
                         f"{e(value.source)}]</span>")
        body = "<br>".join(cells)
        if attr.disputed:
            body += " <span class='warnpill'>sources disagree</span>"
        elif attr.multivalued:
            body += " <span class='dim'>(several)</span>"
        if attr.note:
            body += f"<br><span class='dim'>{e(attr.note)}</span>"
        rows.append(f"<tr><th class='k'>{e(attr.label)}</th><td>{body}</td></tr>")
    return f"<table class='bio'><tbody>{''.join(rows)}</tbody></table>"
