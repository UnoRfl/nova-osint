"""Output renderers: console, JSON, Markdown, CSV and a self-contained HTML report.

``rich`` is used when installed and degraded to plain ANSI when it is not, so
the tool never fails because of a missing pretty-printer.
"""

from __future__ import annotations

import csv
import html as html_mod
import io
import json
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from . import art
from .models import Confidence, Investigation, ModuleStatus, Severity

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    HAVE_RICH = True
except Exception:  # pragma: no cover
    HAVE_RICH = False

SEV_COLOR = {Severity.HIGH: "bold red", Severity.NOTABLE: "yellow", Severity.INFO: "white"}
SEV_MARK = {Severity.HIGH: "!!", Severity.NOTABLE: " *", Severity.INFO: "  "}
CONF_COLOR = {
    Confidence.CONFIRMED: "green",
    Confidence.LIKELY: "cyan",
    Confidence.POSSIBLE: "dim",
}
STATUS_COLOR = {
    ModuleStatus.SUCCESS: "green",
    ModuleStatus.EMPTY: "dim",
    ModuleStatus.PARTIAL: "yellow",
    ModuleStatus.RATE_LIMITED: "yellow",
    ModuleStatus.BLOCKED: "red",
    ModuleStatus.UNAVAILABLE: "red",
    ModuleStatus.FAILED: "bold red",
    ModuleStatus.SKIPPED: "dim",
    ModuleStatus.HUMAN_ACTION: "yellow",
}


def confidence_counts(inv: Investigation) -> dict[str, int]:
    """How much of this report is verified, in one dict.

    An investigator reads the summary before the tables; "31 findings" means
    nothing without knowing how many of them are a registry answer and how many
    are a heuristic guess.
    """
    counts = dict.fromkeys((c.value for c in Confidence), 0)
    for f in inv.findings:
        counts[f.confidence.value] += 1
    return counts


def status_rows(inv: Investigation) -> list[tuple[str, str, str]]:
    """``[(module, status, reason)]`` for every module that did not run cleanly.

    Skipped modules are included: "we never asked" is as important to an
    investigator as "we asked and got nothing".
    """
    rows = [
        (r.module, r.status.value, r.status_reason)
        for r in inv.results
        if not r.status.is_complete
    ]
    rows += [(name, ModuleStatus.SKIPPED.value, reason) for name, reason in inv.skipped]
    return sorted(rows)


#: The eight words a source's availability may be reported with, worst last.
#: They are ordered so a reader scanning the table meets the sources that
#: answered before the ones that could not, and so ``sorted`` puts the
#: problems together.
SOURCE_STATES = ("found", "not found", "not checked", "requires key",
                 "paid", "rate limited", "blocked", "human action required",
                 "unavailable")
_STATE_ORDER = {s: i for i, s in enumerate(SOURCE_STATES)}

_MODULE_STATE = {
    ModuleStatus.SUCCESS: "found",
    ModuleStatus.PARTIAL: "found",
    ModuleStatus.EMPTY: "not found",
    ModuleStatus.RATE_LIMITED: "rate limited",
    ModuleStatus.BLOCKED: "blocked",
    ModuleStatus.UNAVAILABLE: "unavailable",
    ModuleStatus.FAILED: "unavailable",
    ModuleStatus.HUMAN_ACTION: "human action required",
    ModuleStatus.SKIPPED: "not checked",
}


def source_rows(inv: Investigation) -> list[tuple[str, str, str]]:
    """``[(source, state, detail)]`` for every source this run could have used.

    The table that makes the tool's central promise checkable: **"cannot
    access" must never render as "no result"**. A module that ran and found
    nothing, a module that was never asked because it needs a key, a key that
    costs money, and a source that rate limited us are four different answers,
    and a reader who is handed one list of findings cannot tell them apart.

    Sources appear here whether or not they produced anything, which is the
    point - the interesting rows are the ones with no findings behind them.
    """
    rows: dict[str, tuple[str, str]] = {}

    for res in inv.results:
        state = _MODULE_STATE.get(res.status, "unavailable")
        if state == "found" and not res.findings:
            state = "not found"
        detail = res.status_reason
        if not detail and state == "found":
            detail = f"{len(res.findings)} finding(s)"
        rows[res.module] = (state, detail)

    for name, reason in inv.skipped:
        rows[name] = (_skip_state(reason), reason)

    # Sources that are not modules: search engines, browsers, feed adapters.
    for provider, state in sorted(inv.providers.items()):
        if provider in rows:
            continue
        health = str(state.get("health", "unknown"))
        rows[provider] = (_HEALTH_STATE.get(health, "not checked"),
                          str(state.get("reason", "")))

    # A routed need that nothing could answer names its own ladder.
    for route in inv.routes:
        if route.get("found"):
            continue
        need = str(route.get("need", "")).strip()
        if not need or need in rows:
            continue
        rows[need] = ("unavailable", str(route.get("reason", "")))

    return sorted(((name, state, detail) for name, (state, detail) in rows.items()),
                  key=lambda r: (_STATE_ORDER.get(r[1], 99), r[0]))


_STATE_COLOR = {
    "found": "green", "not found": "dim", "not checked": "dim",
    "requires key": "cyan", "paid": "magenta", "rate limited": "yellow",
    "blocked": "red", "human action required": "yellow", "unavailable": "red",
}

_HEALTH_STATE = {
    "ok": "found",
    "unknown": "not checked",
    "rate limited": "rate limited",
    "blocked": "blocked",
    "unavailable": "unavailable",
    "needs key": "requires key",
    "paid": "paid",
    "disabled": "not checked",
    "human action required": "human action required",
}


def _skip_state(reason: str) -> str:
    """Turn "needs $VT_API_KEY" into `requires key` or, honestly, `paid`.

    The distinction is the whole reason this exists: SecurityTrails and
    VirusTotal are both skipped for want of a key, but one of them can be
    fixed in two minutes for nothing and the other costs $500 a month. A
    report that says "requires key" for both has told the reader to go and
    waste an afternoon.
    """
    from .config import KEY_ENV
    from .providers import Availability, availability_of_key

    if "needs $" not in reason.lower():
        return "not checked"
    for name, env in KEY_ENV.items():
        if env in reason or name in reason.lower():
            return ("paid" if availability_of_key(name) is Availability.PAID
                    else "requires key")
    # An unrecognised key name is still a key requirement, not an absence.
    return "requires key"


def declined_rows(inv: Investigation) -> list[tuple[str, float]]:
    """Leads that were found and deliberately not followed, weakest last.

    Declining to follow a lead is a decision, and a report that shows only
    what was pursued hides it. A scan of a common name finds several accounts
    sharing the display name and follows none of them - which is right, and
    which reads as "found nothing" unless it is said out loud.
    """
    expansion = inv.expansion
    return list(getattr(expansion, "below_floor", []) or []) if expansion else []


def declined_note(inv: Investigation) -> str:
    """One line telling the reader how to turn a declined lead into a followed
    one: give the tool something to test the candidates against."""
    if not declined_rows(inv):
        return ""
    return ("These scored below the evidence floor, so none were followed. "
            "Give NOVA something to separate them with - "
            "-K employer=..., -K city=..., -K born=... - and the ones that "
            "match will rise above it.")


def unavailable_sources(inv: Investigation) -> list[tuple[str, str, str]]:
    """Just the rows a reader must not mistake for "nothing was there"."""
    return [r for r in source_rows(inv) if r[1] not in ("found", "not found")]


def _flatten(value: Any, limit: int = 12) -> str:
    if isinstance(value, (list, tuple, set)):
        items = list(value)
        shown = ", ".join(str(i) for i in items[:limit])
        return shown + (f"  (+{len(items) - limit} more)" if len(items) > limit else "")
    return str(value)


# ----------------------------------------------------------------------- console


def connection_rows(inv: Investigation, limit: int = 25
                    ) -> list[tuple[str, str, str, str, str]]:
    """``[(grade, entity, relation, why, reading)]``, best-evidenced first.

    The report's answer to "how do you know these are connected". Every row
    carries the Admiralty grade, the specific observations behind it, and a
    plain-English reading of the number - because a log-odds figure is precise
    and meaningless to anyone who has not read graph.py, and a report that only
    shows the precise version is not actually telling the reader anything.
    """
    graph = inv.graph
    if graph is None or not graph.edges:
        return []
    from .graphview import probability_note

    rows = []
    for edge in sorted(graph.edges.values(), key=lambda e: -e.llr):
        if len(rows) >= limit:
            break
        far = edge.dst if edge.src == graph.seed else edge.src
        node = graph.nodes.get(far)
        label = node.entity.display if node else far
        why = ", ".join(sorted({o.kind for o in edge.observations}))
        rows.append((edge.grade, f"{label}", edge.label, why,
                     probability_note(edge.llr)))
    return rows


#: What the two halves of an Admiralty grade mean, printed once per report so
#: nobody has to look it up. Source reliability and information credibility are
#: separate axes on purpose: collapsing them is how a rumour ends up presented
#: with the confidence of a registry record.
ADMIRALTY_KEY = ("grades are Admiralty: letter = strength of the evidence "
                 "(A best, E disconfirming), digit = independent corroboration "
                 "(1 most, 5 none)")


def render_console(inv: Investigation, *, verbose: bool = False,
                   min_severity: Severity = Severity.INFO) -> str:
    order = {Severity.INFO: 0, Severity.NOTABLE: 1, Severity.HIGH: 2}
    floor = order[min_severity]

    if not HAVE_RICH:
        return _render_plain(inv, floor, order, verbose)

    buf = io.StringIO()
    console = Console(file=buf, width=118, force_terminal=True)
    summary = inv.to_dict()["summary"]
    conf = confidence_counts(inv)
    console.print(
        Panel(
            f"[bold]{inv.target}[/bold]  [dim]({inv.target_type.value})[/dim]\n"
            f"{summary['findings']} findings from {summary['modules_run']} instruments  "
            f"in {inv.duration:.1f}s\n"
            f"[dim]{conf['confirmed']} confirmed, {conf['likely']} likely, "
            f"{conf['possible']} possible[/dim]\n"
            f"[dim]{summary['pivots']} bodies in orbit, {summary['incomplete']} incomplete, "
            f"{summary['skipped']} skipped[/dim]",
            title="[bold]◉ NOVA[/bold]",
            border_style=art.NEBULA[0],
            box=box.ROUNDED,
        )
    )
    # The conclusion, in sentences, before any table. A reader handed eight
    # ranked rows and forty log-odds has been given the working and left to do
    # the last step themselves, and the last step is the one they came for.
    from .analyst import render_text as analyst_text
    from .analyst import write as analyst_write

    note = analyst_write(inv)
    console.print(Panel(analyst_text(note),
                        title="[bold]◆ what I think[/bold]",
                        border_style=art.NEBULA[4], box=box.ROUNDED))

    if inv.resolution is not None:
        # Then the working, for a reader who wants to check it.
        from .identity import render_text as identity_text

        console.print(Panel(
            identity_text(inv.resolution),
            title="[bold]◈ which one is your subject[/bold]",
            border_style=art.NEBULA[3], box=box.ROUNDED))

    if not inv.findings:
        console.print(art.render(art.QUIET_SKY), end="")

    for res in inv.results:
        shown = [f for f in res.findings if order[f.severity] >= floor]
        if not shown and not (verbose and res.errors):
            continue
        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold cyan",
            expand=True,
            pad_edge=False,
            title=f"[bold]{art.glyph(res.module)} {res.module}[/bold]  [dim]{res.duration:.1f}s[/dim]",
            title_justify="left",
            title_style="none",
        )
        # Fixed widths on everything but the value column, so the value gets
        # all the slack instead of the table spreading its padding around.
        table.add_column("", width=2, no_wrap=True)
        table.add_column("field", style="bold", width=30, overflow="fold")
        table.add_column("value", overflow="fold", ratio=1)
        table.add_column("src", style="dim", width=16, no_wrap=True)
        for f in shown:
            value = _flatten(f.value)
            if f.url and f.url != str(f.value):
                value = f"{value}\n[dim blue]{f.url}[/dim blue]"
            table.add_row(
                f"[{SEV_COLOR[f.severity]}]{SEV_MARK[f.severity].strip() or ''}[/]",
                f"[{CONF_COLOR[f.confidence]}]{f.label}[/]",
                value,
                f.source,
            )
        console.print(table)
        for err in res.errors:
            console.print(f"  [yellow]warn[/yellow] [dim]{res.module}:[/dim] {err}")
        console.print()

    rows = status_rows(inv)
    if rows:
        # The most important table in a long scan: it is the difference between
        # "there was nothing to find" and "we never got to look".
        st = Table(box=box.SIMPLE, show_header=True, header_style="bold yellow", expand=True)
        st.add_column("instrument", width=16, no_wrap=True)
        st.add_column("status", width=14, no_wrap=True)
        st.add_column("reason", style="dim", overflow="fold")
        for name, status, reason in rows:
            colour = STATUS_COLOR.get(ModuleStatus(status), "white")
            st.add_row(name, f"[{colour}]{status}[/]", reason or "-")
        console.print(
            Panel(st, title="[bold]instruments that did not report cleanly[/bold]",
                  border_style="yellow", box=box.ROUNDED)
        )

    gaps = unavailable_sources(inv)
    if gaps:
        at = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta",
                   expand=True)
        at.add_column("source", width=18, no_wrap=True)
        at.add_column("availability", width=22, no_wrap=True)
        at.add_column("what that means", style="dim", overflow="fold")
        for name, state, detail in gaps:
            at.add_row(name, f"[{_STATE_COLOR.get(state, 'white')}]{state}[/]",
                       detail or "-")
        console.print(
            Panel(at, title="[bold]sources not consulted[/bold]",
                  subtitle="[dim]these are gaps in coverage, not absences of "
                           "evidence[/dim]",
                  border_style="magenta", box=box.ROUNDED)
        )

    declined = declined_rows(inv)
    if declined:
        dt = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan",
                   expand=True)
        dt.add_column("lead", overflow="fold")
        dt.add_column("score", width=10, no_wrap=True)
        for eid, score in declined[:12]:
            dt.add_row(eid, f"{score:.4f}")
        console.print(
            Panel(dt, title="[bold]found, not followed[/bold]",
                  subtitle=f"[dim]{declined_note(inv)}[/dim]",
                  border_style="cyan", box=box.ROUNDED)
        )

    links = connection_rows(inv)
    if links:
        lt = Table(box=box.SIMPLE, show_header=True, header_style="bold green",
                   expand=True, pad_edge=False)
        lt.add_column("grade", max_width=6)
        lt.add_column("connected to")
        lt.add_column("how", max_width=18)
        lt.add_column("evidence", style="dim")
        lt.add_column("reading", style="dim", max_width=22)
        for grade, label, relation, why, reading in links:
            colour = ("bold green" if grade[0] == "A" else
                      "green" if grade[0] == "B" else
                      "yellow" if grade[0] == "C" else
                      "red" if grade[0] == "E" else "white")
            lt.add_row(f"[{colour}]{grade}[/]", label, relation, why, reading)
        console.print(
            Panel(lt, title="[bold]how the pieces connect[/bold]",
                  border_style="green", box=box.ROUNDED)
        )
        # On its own line, not as the panel's subtitle: rich truncates a
        # subtitle to the border width and a legend cut off mid-word
        # ("...independent corroborat") is worse than no legend.
        console.print(f"  [dim]{ADMIRALTY_KEY}[/dim]")

    if inv.pivots:
        p = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta", expand=True)
        p.add_column("pivot")
        p.add_column("type", max_width=10)
        p.add_column("why", style="dim")
        for piv in inv.pivots[:40]:
            p.add_row(piv.target, piv.target_type.value, piv.reason)
        console.print(
            Panel(p, title="[bold]✦ bodies in orbit[/bold]  [dim]scan these next[/dim]",
                  border_style=art.NEBULA[-1], box=box.ROUNDED)
        )

    return buf.getvalue()


def _render_plain(inv: Investigation, floor: int, order: dict, verbose: bool) -> str:
    out: list[str] = []
    s = inv.to_dict()["summary"]
    out.append("=" * 78)
    out.append(f"  {inv.target}  ({inv.target_type.value})")
    out.append(f"  {s['findings']} findings / {s['modules_run']} modules / {s['errors']} errors")
    conf = confidence_counts(inv)
    out.append(f"  confirmed {conf['confirmed']} / likely {conf['likely']} "
               f"/ possible {conf['possible']}")
    out.append("=" * 78)
    for res in inv.results:
        shown = [f for f in res.findings if order[f.severity] >= floor]
        if not shown:
            continue
        out.append(f"\n[{res.module}]")
        for f in shown:
            out.append(f"  {SEV_MARK[f.severity]} {f.label}: {_flatten(f.value)}")
            if f.url and f.url != str(f.value):
                out.append(f"       {f.url}")
        for err in res.errors:
            out.append(f"  warn: {err}")
    rows = status_rows(inv)
    if rows:
        out.append("\n[instrument status]")
        for name, status, reason in rows:
            out.append(f"  {name}: {status}{' - ' + reason if reason else ''}")
    gaps = unavailable_sources(inv)
    if gaps:
        out.append("\n[sources not consulted]  gaps in coverage, not absences of evidence")
        for name, state, detail in gaps:
            out.append(f"  {name}: {state}{' - ' + detail if detail else ''}")
    links = connection_rows(inv)
    if links:
        out.append("\n[how the pieces connect]")
        for grade, label, relation, why, reading in links:
            out.append(f"  {grade}  {label}  ({relation}; {why}) - {reading}")
        out.append(f"  {ADMIRALTY_KEY}")
    if inv.pivots:
        out.append("\n[pivots]")
        for p in inv.pivots[:40]:
            out.append(f"  {p.target} ({p.target_type.value}) - {p.reason}")
    return "\n".join(out)


# -------------------------------------------------------------------- machine


def render_json(inv: Investigation, pivots: Iterable[Investigation] = ()) -> str:
    payload = inv.to_dict()
    extra = [p.to_dict() for p in pivots]
    if extra:
        payload["pivot_scans"] = extra
    return json.dumps(payload, indent=2, default=str)


def render_csv(inv: Investigation) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(inv.started_at))
    # `method` is appended rather than inserted so a spreadsheet or script
    # built against the old column order keeps working.
    w.writerow(["target", "target_type", "module", "module_status", "severity",
                "confidence", "label", "value", "source", "url", "timestamp",
                "method", "provider"])
    for res in inv.results:
        for f in res.findings:
            acq = f.acquisition
            w.writerow([inv.target, inv.target_type.value, res.module, res.status.value,
                        f.severity.value, f.confidence.value, f.label,
                        _flatten(f.value, 999), f.source, f.url or "", stamp,
                        f.method, acq.provider if acq else ""])
    # Modules that never ran, or ran badly, get a row of their own: a CSV that
    # silently omits them reads as "we checked and there was nothing there".
    for name, status, reason in status_rows(inv):
        if any(r.module == name and r.findings for r in inv.results):
            continue
        w.writerow([inv.target, inv.target_type.value, name, status, Severity.INFO.value,
                    "", "module status", reason, "nova", "", stamp, "", ""])
    # And the sources that were never consulted at all, for the same reason
    # one rung up: a source needing a key is not a source that found nothing.
    for name, state, detail in unavailable_sources(inv):
        if any(r.module == name for r in inv.results):
            continue
        w.writerow([inv.target, inv.target_type.value, name, state, Severity.INFO.value,
                    "", "source availability", detail, "nova", "", stamp, "", ""])
    return buf.getvalue()


#: Targets that are a *who* rather than a *what*, and so get the dossier
#: treatment at the top of the report.
_PERSONAL = ("person", "username", "email")


def _markdown_profile(inv: Investigation) -> list[str]:
    """Who the subject is, before the module-by-module dump.

    The markdown export was the one format that never got the investigation
    layer: it still rendered the flat "here is what each module said" report
    from before any of it existed. A person scan exported to a file therefore
    arrived with no biography, no account list and no candidate warning - the
    three things that make it a dossier rather than a log.
    """
    if inv.target_type.value not in _PERSONAL:
        return []
    from .biography import render_markdown as bio_md
    from .profile import build as build_profile
    from .socials import render_markdown as socials_md

    try:
        profile = build_profile(inv)
    except Exception:  # pragma: no cover - a profile must never lose the report
        return []

    out: list[str] = []
    if profile.ambiguities or profile.candidates:
        # First, and before any fact about any of them. A report that opens
        # with an employer has already told the reader it knows who this is.
        out += ["## Who this might be", ""]
        for note in profile.ambiguities:
            out.append(f"> **{note}**")
        if profile.ambiguities:
            out.append("")
        if profile.candidates:
            out += ["Best corroborated first. NOVA has not decided which of "
                    "these is your subject, and nothing below should be read "
                    "as if it had.", "",
                    "| Grade | Candidate | Relevance | Why | Sources |",
                    "|---|---|---|---|---|"]
            for c in profile.candidates:
                out.append(f"| `{c.grade}` | {c.value} | {c.score:.3f} "
                           f"| {c.why} | {', '.join(c.sources) or '-'} |")
            out.append("")

    bio = bio_md(profile.bio)
    if bio:
        out += ["## Who", "", bio]

    socials = socials_md(profile.socials)
    if socials:
        out += ["## Accounts", "", socials]
    return out


def render_markdown(inv: Investigation) -> str:
    s = inv.to_dict()["summary"]
    conf = confidence_counts(inv)
    out = [
        f"# OSINT report: `{inv.target}`",
        "",
        f"- **Type:** {inv.target_type.value}",
        f"- **Generated:** {time.strftime('%Y-%m-%d %H:%M:%S %Z')}",
        f"- **Scan duration:** {inv.duration:.1f}s",
        "",
        "## Summary",
        "",
        "| | Count |",
        "|---|---|",
        f"| Findings | {s['findings']} |",
        f"| Confirmed (authoritative source) | {conf['confirmed']} |",
        f"| Likely (strong heuristic) | {conf['likely']} |",
        f"| Possible (weak or ambiguous) | {conf['possible']} |",
        f"| Modules run | {s['modules_run']} |",
        f"| Modules incomplete | {s['incomplete']} |",
        f"| Modules skipped | {s['skipped']} |",
        "",
    ]
    from .analyst import render_markdown as analyst_md
    from .analyst import write as analyst_write

    out += ["## What I think", "", analyst_md(analyst_write(inv))]
    if inv.resolution is not None:
        from .identity import render_markdown as identity_md

        out += ["## Which one is your subject", "",
                identity_md(inv.resolution)]
    out += _markdown_profile(inv)
    rows = status_rows(inv)
    if rows:
        out += [
            "### Coverage gaps",
            "",
            "Everything below either did not run or did not finish. Treat the "
            "absence of findings from these sources as *unknown*, not as *none*.",
            "",
            "| Module | Status | Reason |",
            "|---|---|---|",
        ]
        out += [f"| {name} | {status} | {reason or '-'} |" for name, status, reason in rows]
        out.append("")
    gaps = unavailable_sources(inv)
    if gaps:
        out += [
            "### Source availability",
            "",
            "Sources that were **not** consulted, and why. A source that "
            "requires a key, costs money or rate limited us has told you "
            "nothing - which is different from telling you there is nothing.",
            "",
            "| Source | Availability | Detail |",
            "|---|---|---|",
        ]
        out += [f"| {name} | {state} | {detail or '-'} |" for name, state, detail in gaps]
        out.append("")
    declined = declined_rows(inv)
    if declined:
        out += [
            "### Leads found but not followed",
            "",
            declined_note(inv),
            "",
            "| Lead | Score |",
            "|---|---|",
        ]
        out += [f"| `{eid}` | {score:.4f} |" for eid, score in declined[:15]]
        out.append("")
    links = connection_rows(inv)
    if links:
        out += [
            "### How the pieces connect",
            "",
            f"Each row is a link the scan drew, and why. {ADMIRALTY_KEY.capitalize()}.",
            "",
            "| Grade | Connected to | How | Evidence | Reading |",
            "|---|---|---|---|---|",
        ]
        out += [f"| `{grade}` | {label} | {relation} | {why} | {reading} |"
                for grade, label, relation, why, reading in links]
        out.append("")
    high = [f for f in inv.findings if f.severity == Severity.HIGH]
    if high:
        out += ["## Highlights", ""]
        for f in high:
            link = f" <{f.url}>" if f.url else ""
            out.append(f"- **{f.label}** - {_flatten(f.value, 20)}{link}")
        out.append("")
    for res in inv.results:
        if not res.findings and not res.errors:
            continue
        heading = f"## {res.module}"
        if not res.status.is_complete:
            heading += f" — {res.status.value}"
        out += [heading, "", "| | Field | Value | Source |", "|---|---|---|---|"]
        for f in res.findings:
            mark = {Severity.HIGH: "!!", Severity.NOTABLE: "*", Severity.INFO: ""}[f.severity]
            value = _flatten(f.value, 20).replace("|", "\\|")
            if f.url:
                value = f"[{value}]({f.url})" if f.url != str(f.value) else f"<{f.url}>"
            out.append(f"| {mark} | {f.label} | {value} | {f.source} |")
        out.append("")
        for err in res.errors:
            out.append(f"> warning: {err}")
        out.append("")
    if inv.pivots:
        out += ["## Pivots", ""]
        for p in inv.pivots:
            out.append(f"- `{p.target}` ({p.target_type.value}) - {p.reason}")
    return "\n".join(out)


# ------------------------------------------------------------------------ html

HTML_CSS = """
:root{--bg:#fbfbfd;--panel:#fff;--ink:#16181d;--muted:#666d7a;--line:#e4e7ec;
--accent:#3b6ef6;--high:#c5303a;--notable:#a2650b;--ok:#1a7f4b;}
@media (prefers-color-scheme:dark){:root{--bg:#0f1116;--panel:#161922;--ink:#e6e8ee;
--muted:#99a1b0;--line:#272b36;--accent:#7aa2ff;--high:#ff6b74;--notable:#e0a844;--ok:#4ade80;}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,BlinkMacSystemFont,
"Segoe UI",Roboto,Helvetica,Arial,sans-serif;padding:32px 16px}
.wrap{max-width:1040px;margin:0 auto}
h1{font-size:1.6rem;margin:0 0 4px;letter-spacing:-.02em}
h1 code{background:none;color:var(--accent)}
.sub{color:var(--muted);font-size:.9rem;margin-bottom:24px}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:26px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:10px 16px;min-width:110px}
.card b{display:block;font-size:1.45rem;line-height:1.1}
.card span{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.06em}
section{background:var(--panel);border:1px solid var(--line);border-radius:12px;
margin-bottom:18px;overflow:hidden}
section>h2{margin:0;padding:12px 18px;font-size:.95rem;border-bottom:1px solid var(--line);
display:flex;justify-content:space-between;align-items:center}
section>h2 em{font-style:normal;color:var(--muted);font-weight:400;font-size:.8rem}
table{width:100%;border-collapse:collapse;font-size:.88rem}
td{padding:8px 18px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:none}
td.k{width:230px;font-weight:600;color:var(--muted)}
td.v{word-break:break-word}
td.s{width:110px;color:var(--muted);font-size:.78rem;text-align:right;white-space:nowrap}
tr.high td.k{color:var(--high)} tr.notable td.k{color:var(--notable)}
a{color:var(--accent)} .u{display:block;font-size:.78rem;opacity:.8;word-break:break-all}
.warn{padding:8px 18px;color:var(--notable);font-size:.82rem;border-top:1px dashed var(--line)}
.pivot{display:inline-block;background:var(--bg);border:1px solid var(--line);border-radius:999px;
padding:3px 11px;margin:3px;font-size:.82rem}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em;
background:var(--bg);padding:1px 5px;border-radius:4px}
footer{color:var(--muted);font-size:.78rem;margin-top:28px;text-align:center}
"""


def render_html(inv: Investigation) -> str:
    e = html_mod.escape
    s = inv.to_dict()["summary"]
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>OSINT report - {e(inv.target)}</title><style>{HTML_CSS}</style></head><body>",
        "<div class='wrap'>",
        f"<h1>OSINT report &middot; <code>{e(inv.target)}</code></h1>",
        f"<div class='sub'>{e(inv.target_type.value)} &middot; generated "
        f"{time.strftime('%Y-%m-%d %H:%M')} &middot; {inv.duration:.1f}s</div>",
        "<div class='cards'>",
        f"<div class='card'><b>{s['findings']}</b><span>findings</span></div>",
        f"<div class='card'><b>{s['modules_run']}</b><span>modules</span></div>",
        f"<div class='card'><b>{len([f for f in inv.findings if f.severity == Severity.HIGH])}"
        "</b><span>high interest</span></div>",
        f"<div class='card'><b>{s['pivots']}</b><span>pivots</span></div>",
        f"<div class='card'><b>{s['incomplete'] + s['skipped']}</b>"
        "<span>coverage gaps</span></div>",
        "</div>",
    ]
    links = connection_rows(inv)
    if links:
        parts.append(
            "<section><h2>How the pieces connect"
            f"<em>{e(ADMIRALTY_KEY)}</em></h2>"
            "<table><thead><tr><th>Grade</th><th>Connected to</th><th>How</th>"
            "<th>Evidence</th><th>Reading</th></tr></thead><tbody>"
        )
        for grade, label, relation, why, reading in links:
            parts.append(
                f"<tr><td><code>{e(grade)}</code></td><td>{e(label)}</td>"
                f"<td>{e(relation)}</td><td>{e(why)}</td><td>{e(reading)}</td></tr>"
            )
        parts.append("</tbody></table></section>")

    gaps = status_rows(inv)
    if gaps:
        parts.append(
            "<section><h2>Coverage gaps<em>absence of evidence, not evidence of absence</em>"
            "</h2><table>"
        )
        for name, status, reason in gaps:
            parts.append(
                f"<tr class='notable'><td class='k'>{e(name)}</td>"
                f"<td class='v'>{e(status)}</td><td class='s'>{e(reason or '-')}</td></tr>"
            )
        parts.append("</table></section>")
    unavailable = unavailable_sources(inv)
    if unavailable:
        parts.append(
            "<section><h2>Source availability<em>what was never consulted, and "
            "why</em></h2><table>"
        )
        for name, state, detail in unavailable:
            parts.append(
                f"<tr class='notable'><td class='k'>{e(name)}</td>"
                f"<td class='v'>{e(state)}</td><td class='s'>{e(detail or '-')}</td></tr>"
            )
        parts.append("</table></section>")
    for res in inv.results:
        if not res.findings and not res.errors:
            continue
        parts.append(
            f"<section><h2>{e(res.module)}<em>{len(res.findings)} findings &middot; "
            f"{res.duration:.1f}s</em></h2><table>"
        )
        for f in res.findings:
            cls = f.severity.value if f.severity != Severity.INFO else ""
            value = e(_flatten(f.value, 60))
            if f.url:
                value += f"<a class='u' href='{e(f.url)}' rel='noopener noreferrer'>{e(f.url)}</a>"
            parts.append(
                f"<tr class='{cls}'><td class='k'>{e(f.label)}</td>"
                f"<td class='v'>{value}</td><td class='s'>{e(f.source)}</td></tr>"
            )
        parts.append("</table>")
        for err in res.errors:
            parts.append(f"<div class='warn'>{e(err)}</div>")
        parts.append("</section>")

    if inv.pivots:
        chips = "".join(
            f"<span class='pivot'><code>{e(p.target)}</code> &middot; {e(p.reason)}</span>"
            for p in inv.pivots
        )
        parts.append(f"<section><h2>Pivots<em>next targets</em></h2><div style='padding:12px'>{chips}</div></section>")

    parts += [
        "<footer>Generated by OSINT Suite from public sources. "
        "Verify every finding before acting on it.</footer>",
        "</div></body></html>",
    ]
    return "".join(parts)


def render_graph(inv: Investigation) -> str:
    from .graphview import render_graph_html

    return render_graph_html(inv)


def render_graphml_report(inv: Investigation) -> str:
    from .graphview import render_graphml

    return render_graphml(inv)


RENDERERS = {
    "console": lambda inv: render_console(inv),
    "json": render_json,
    "csv": render_csv,
    "markdown": render_markdown,
    "md": render_markdown,
    "html": render_html,
    #: The investigation as a picture. Self-contained: no CDN, no network, so
    #: it still works attached to a case file on an offline machine.
    "graph": render_graph,
    #: For Gephi / yEd / Cytoscape, which do link analysis properly.
    "graphml": render_graphml_report,
    #: The dossier: the same investigation organised around the subject rather
    #: than around which module happened to find what.
    "profile": lambda inv: _profile("text", inv),
    "profile-html": lambda inv: _profile("html", inv),
    "profile-json": lambda inv: _profile("json", inv),
    #: The phone answer card. Useful from `nova scan` too, so a phone number
    #: inside a larger pipeline renders the same way `nova phone` shows it.
    "card": lambda inv: _card(inv),
    #: The consolidated biographical dossier: one subject, every field carrying
    #: its competing values and their sources. See core/target_dossier.py.
    "dossier": lambda inv: _target_dossier("markdown", inv),
    "dossier-json": lambda inv: _target_dossier("json", inv),
}


def _target_dossier(fmt: str, inv: Investigation) -> str:
    """Render the unified dossier. Imported lazily to keep the import graph flat."""
    from .target_dossier import generate_target_dossier, render_json, render_markdown

    dossier = generate_target_dossier(inv)
    return render_json(dossier) if fmt == "json" else render_markdown(dossier)


def _card(inv: Investigation) -> str:
    from .phonecard import build, render_text

    return render_text(build(inv))


def _profile(kind: str, inv: Investigation) -> str:
    from . import dossier

    return {"text": dossier.render_profile_text,
            "html": dossier.render_profile_html,
            "json": dossier.render_profile_json}[kind](inv)


def write(inv: Investigation, path: Path, fmt: str | None = None) -> Path:
    fmt = fmt or path.suffix.lstrip(".").lower() or "json"
    renderer = RENDERERS.get(fmt)
    if renderer is None:
        raise ValueError(f"unknown format: {fmt}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(renderer(inv), "utf-8")
    return path
