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


def _flatten(value: Any, limit: int = 12) -> str:
    if isinstance(value, (list, tuple, set)):
        items = list(value)
        shown = ", ".join(str(i) for i in items[:limit])
        return shown + (f"  (+{len(items) - limit} more)" if len(items) > limit else "")
    return str(value)


# ----------------------------------------------------------------------- console


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
    w.writerow(["target", "target_type", "module", "module_status", "severity",
                "confidence", "label", "value", "source", "url", "timestamp"])
    for res in inv.results:
        for f in res.findings:
            w.writerow([inv.target, inv.target_type.value, res.module, res.status.value,
                        f.severity.value, f.confidence.value, f.label,
                        _flatten(f.value, 999), f.source, f.url or "", stamp])
    # Modules that never ran, or ran badly, get a row of their own: a CSV that
    # silently omits them reads as "we checked and there was nothing there".
    for name, status, reason in status_rows(inv):
        if any(r.module == name and r.findings for r in inv.results):
            continue
        w.writerow([inv.target, inv.target_type.value, name, status, Severity.INFO.value,
                    "", "module status", reason, "nova", "", stamp])
    return buf.getvalue()


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


RENDERERS = {
    "console": lambda inv: render_console(inv),
    "json": render_json,
    "csv": render_csv,
    "markdown": render_markdown,
    "md": render_markdown,
    "html": render_html,
}


def write(inv: Investigation, path: Path, fmt: str | None = None) -> Path:
    fmt = fmt or path.suffix.lstrip(".").lower() or "json"
    renderer = RENDERERS.get(fmt)
    if renderer is None:
        raise ValueError(f"unknown format: {fmt}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(renderer(inv), "utf-8")
    return path
