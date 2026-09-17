"""Rendering a :class:`~nova_osint.core.profile.Profile` for a reader.

Text for the terminal, HTML for something you can send. Both put the same three
things above everything else, in this order:

1. **Who this might not be.** When the subject is a name, the candidate list and
   the ambiguity warnings come first, before a single fact about any of them. A
   dossier that opens with an employer has already told the reader it knows who
   the subject is.
2. **The relationships**, with connections *between other people* ahead of
   connections to the subject, because those are what a flat scan can never
   produce.
3. **What was not looked at.** Coverage gaps travel with the document rather
   than living in a scan log nobody keeps.
"""

from __future__ import annotations

import html as html_mod
import time

from .models import Investigation
from .profile import SECTIONS, Profile, build, confidence_line

BAR = "=" * 78


def render_text(profile: Profile) -> str:
    out: list[str] = []
    out.append(BAR)
    out.append(f"  PROFILE: {profile.subject}   ({profile.subject_type})")
    out.append(f"  {profile.entities} entities, {profile.findings} findings, "
               f"{len(profile.relationships)} relationships, {profile.duration:.1f}s")
    out.append(BAR)

    if profile.ambiguities or profile.candidates:
        out.append("\n## WHO THIS IS  —  read before anything below")
        for note in profile.ambiguities:
            out.append(f"  ! {note}")
        if profile.candidates:
            out.append("\n  candidates, best corroborated first:")
            for c in profile.candidates:
                out.append(f"    {c.grade}  rel {c.score:5.3f}  {c.value}"
                           f"   [{c.why}]  via {', '.join(c.sources) or '-'}")
            out.append("\n  NOVA has not decided which of these is your subject,"
                       "\n  and nothing below should be read as if it had.")

    out.append(f"\n## ASSESSMENT\n  {confidence_line(profile)}")
    if profile.truncated:
        out.append(f"  This profile is incomplete: the scan stopped on "
                   f"{profile.truncated}.")

    if profile.relationships:
        out.append("\n## RELATIONSHIPS")
        indirect = [r for r in profile.relationships if r.indirect]
        direct = [r for r in profile.relationships if not r.indirect]
        if indirect:
            out.append("  between other parties (not directly to the subject):")
            for r in indirect[:30]:
                out.append(f"    {r.grade}  {r.a}  --{r.relation}-->  {r.b}"
                           f"   [{r.why}]")
        if direct:
            out.append("  to the subject:")
            for r in direct[:40]:
                out.append(f"    {r.grade}  {r.relation:<18} {r.b}"
                           f"   [{r.why}] - {r.reading}")

    for heading, _kinds, note in SECTIONS:
        entries = profile.sections.get(heading, [])
        out.append(f"\n## {heading.upper()}   ({len(entries)})")
        out.append(f"  {note}")
        if not entries:
            # Printed empty on purpose: a missing heading reads as "nothing
            # there", which is a different claim from "we looked and found none".
            out.append("  (none found)")
            continue
        for e in entries:
            seen = f"{e.corroboration} source" + ("s" if e.corroboration != 1 else "")
            out.append(f"    {e.grade}  rel {e.score:5.3f}  {e.value}"
                       f"   [{e.why}; {seen}]")

    if profile.timeline:
        out.append("\n## TIMELINE")
        for when, what, module in profile.timeline:
            out.append(f"    {when}  {what}   ({module})")

    if profile.exposure:
        out.append("\n## EXPOSURE  —  high-interest findings")
        for label, value, module in profile.exposure[:40]:
            out.append(f"    {label}: {value}   ({module})")

    out.append("\n## COVERAGE GAPS")
    if profile.gaps:
        out.append("  These sources did not answer. Absence here is not evidence"
                   " of absence.")
        for gap in profile.gaps:
            out.append(f"    {gap}")
    else:
        out.append("  every source answered.")
    out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# html
# ---------------------------------------------------------------------------

_CSS = """
:root{--bg:#0d0d14;--fg:#e9e7f2;--dim:#8f8ca6;--line:#26243c;--accent:#7c5cff;
      --warn:#ffb3c8;--ok:#5ee6a8}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
     font:15px/1.6 ui-sans-serif,system-ui,'Segoe UI',sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:32px 20px 80px}
h1{font-size:26px;margin:0 0 4px}
h1 code{color:var(--accent);font-size:24px}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.1em;color:var(--dim);
   border-bottom:1px solid var(--line);padding-bottom:6px;margin:34px 0 12px}
h2 em{float:right;text-transform:none;letter-spacing:0;font-style:normal;
      font-size:11px;color:var(--dim)}
.sub{color:var(--dim);margin-bottom:22px}
.warn{background:#331a24;border-left:3px solid var(--warn);padding:12px 16px;
      border-radius:5px;margin:14px 0}
.warn b{color:var(--warn)}
.note{color:var(--dim);font-size:13px;margin:-6px 0 12px}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;color:var(--dim);font-weight:600;font-size:11px;
   text-transform:uppercase;letter-spacing:.07em;padding:6px 8px;
   border-bottom:1px solid var(--line)}
td{padding:7px 8px;border-bottom:1px solid #1a1828;vertical-align:top;
   word-break:break-word}
tr:hover td{background:#15131f}
code,.g{font-family:ui-monospace,'Cascadia Code',monospace;font-size:12px}
.g{padding:1px 6px;border-radius:4px;font-weight:700}
.gA{background:#0f3d2b;color:#5ee6a8}.gB{background:#123a45;color:#67d8f0}
.gC{background:#3d3413;color:#f0d267}.gD{background:#2a2734;color:#a6a2bb}
.gE{background:#3d1520;color:#ff8fa8}
.empty{color:var(--dim);font-style:italic;padding:8px}
.dim{color:var(--dim)}
"""


def render_html(profile: Profile) -> str:
    e = html_mod.escape
    p: list[str] = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>Profile - {e(profile.subject)}</title><style>{_CSS}</style>",
        "</head><body><div class='wrap'>",
        f"<h1>Profile &middot; <code>{e(profile.subject)}</code></h1>",
        f"<div class='sub'>{e(profile.subject_type)} &middot; "
        f"{profile.entities} entities &middot; {profile.findings} findings &middot; "
        f"{len(profile.relationships)} relationships &middot; "
        f"generated {time.strftime('%Y-%m-%d %H:%M')}</div>",
    ]

    if profile.ambiguities or profile.candidates:
        p.append("<div class='warn'><b>Who this is has not been established.</b><br>")
        for note in profile.ambiguities:
            p.append(f"{e(note)}<br>")
        p.append("NOVA has not decided which candidate is your subject, and nothing "
                 "below should be read as if it had.</div>")
        if profile.candidates:
            p.append("<h2>Candidates<em>best corroborated first</em></h2>")
            p.append(_table(["", "Candidate", "Relevance", "Evidence", "Seen by"],
                            [[_grade(c.grade), e(c.value), f"{c.score:.3f}",
                              e(c.why), e(", ".join(c.sources))]
                             for c in profile.candidates]))

    p.append(f"<h2>Assessment</h2><p>{e(confidence_line(profile))}</p>")
    if profile.truncated:
        p.append(f"<div class='warn'>This profile is <b>incomplete</b>: the scan "
                 f"stopped on {e(profile.truncated)}.</div>")

    if profile.relationships:
        indirect = [r for r in profile.relationships if r.indirect]
        direct = [r for r in profile.relationships if not r.indirect]
        if indirect:
            p.append("<h2>Relationships between other parties"
                     "<em>not directly to the subject</em></h2>")
            p.append(_table(["", "From", "Relation", "To", "Evidence"],
                            [[_grade(r.grade), e(r.a), e(r.relation), e(r.b),
                              e(r.why)] for r in indirect[:40]]))
        if direct:
            p.append("<h2>Relationships to the subject</h2>")
            p.append(_table(["", "Relation", "Entity", "Evidence", "Reading"],
                            [[_grade(r.grade), e(r.relation), e(r.b), e(r.why),
                              e(r.reading)] for r in direct[:60]]))

    for heading, _kinds, note in SECTIONS:
        entries = profile.sections.get(heading, [])
        p.append(f"<h2>{e(heading)}<em>{e(note)}</em></h2>")
        if not entries:
            p.append("<div class='empty'>none found</div>")
            continue
        p.append(_table(["", "Value", "Relevance", "Sources", "Evidence"],
                        [[_grade(x.grade), e(x.value), f"{x.score:.3f}",
                          str(x.corroboration), e(x.why)] for x in entries]))

    if profile.timeline:
        p.append("<h2>Timeline</h2>")
        p.append(_table(["When", "What", "Source"],
                        [[e(w), e(what), e(m)] for w, what, m in profile.timeline]))

    if profile.exposure:
        p.append("<h2>Exposure<em>high-interest findings</em></h2>")
        p.append(_table(["Finding", "Value", "Module"],
                        [[e(a), e(b), e(c)] for a, b, c in profile.exposure[:60]]))

    p.append("<h2>Coverage gaps<em>absence of evidence, not evidence of absence"
             "</em></h2>")
    if profile.gaps:
        p.append("<ul>" + "".join(f"<li>{e(g)}</li>" for g in profile.gaps) + "</ul>")
    else:
        p.append("<div class='empty'>every source answered</div>")

    p.append("</div></body></html>")
    return "\n".join(p)


def _grade(grade: str) -> str:
    letter = (grade or "E")[0]
    return f"<span class='g g{letter}'>{html_mod.escape(grade)}</span>"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{h}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>"
                   for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


# ---------------------------------------------------------------------------
# renderer entry points
# ---------------------------------------------------------------------------


def render_profile_text(inv: Investigation) -> str:
    return render_text(build(inv))


def render_profile_html(inv: Investigation) -> str:
    return render_html(build(inv))


def render_profile_json(inv: Investigation) -> str:
    import json

    return json.dumps(build(inv).to_dict(), indent=2, default=str)
