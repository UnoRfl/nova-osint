"""``nova calibrate``: score the evidence table against links somebody checked.

Three actions, and the order they are meant to be used in:

``export``   take a saved case and write its edges out as corpus rows with the
             label left blank. This is the only honest way to build a corpus -
             from links the operator actually pursued and then established the
             truth of.
``report``   score the current table against a labelled corpus and print the
             reliability table and the suggested weights.
``selftest`` prove the harness itself on a corpus whose truth is known by
             construction. This one measures NOVA's measuring instrument, which
             is the one thing a calibration harness must not take on faith.

Nothing here edits ``graph.EVIDENCE``. It prints a diff.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any

from .core.calibration import (
    Case,
    ObservationSpec,
    evaluate,
    load_corpus,
    render_text,
    save_corpus,
)

EXIT_OK = 0
EXIT_NO_FINDINGS = 1
EXIT_USAGE = 2


def add_parsers(sub: Any, common: Any) -> None:
    cal = sub.add_parser(
        "calibrate",
        help="score the evidence table against links whose truth you know")
    cal.add_argument("action", nargs="?", default="report",
                     choices=("report", "export", "selftest"))
    cal.add_argument("corpus", nargs="?", default="",
                     help="JSONL corpus for `report`, or the case id for `export`")
    cal.add_argument("-o", "--out", default="", metavar="FILE",
                     help="where `export` writes")
    cal.add_argument("--json", action="store_true", dest="as_json",
                     help="machine-readable report")
    cal.add_argument("--min-cases", type=int, default=None,
                     help="cases needed before a weight is suggested")
    cal.add_argument("--prior", type=float, default=None, metavar="N",
                     help="how hard to pull the fit back toward the current "
                          "table, in pseudo-cases; lower it when you have a lot "
                          "of adjudicated data")
    common(cal)


# ---------------------------------------------------------------------------


def cmd_calibrate(args: argparse.Namespace, cfg: Any,
                  open_store: Any = None) -> int:
    if args.action == "selftest":
        return _selftest(args)
    if args.action == "export":
        return _export(args, cfg, open_store)
    return _report(args)


def _report(args: argparse.Namespace) -> int:
    if not args.corpus:
        print("usage: nova calibrate report CORPUS.jsonl\n\n"
              "Build one with:  nova calibrate export <case-id> -o corpus.jsonl\n"
              "then set \"label\": true or false on each row you can vouch for.",
              file=sys.stderr)
        return EXIT_USAGE
    path = Path(args.corpus)
    if not path.exists():
        print(f"no corpus at {path}", file=sys.stderr)
        return EXIT_USAGE

    cases, problems = load_corpus(path)
    if not cases:
        print(f"{path} holds no usable cases", file=sys.stderr)
        for p in problems[:10]:
            print(f"  {p}", file=sys.stderr)
        return EXIT_NO_FINDINGS

    kw: dict[str, Any] = {}
    if args.min_cases is not None:
        kw["min_cases"] = args.min_cases
    if args.prior is not None:
        kw["prior_strength"] = args.prior
    report = evaluate(cases, **kw)
    report.problems = problems + report.problems

    if args.as_json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(render_text(report))
    return EXIT_OK


def _export(args: argparse.Namespace, cfg: Any, open_store: Any) -> int:
    """Turn a saved case's edges into corpus rows with the label left blank.

    Left blank deliberately. The tool must never guess the answer it is about
    to be graded against - a corpus seeded with NOVA's own opinion measures
    nothing but NOVA's consistency, and would come back beautifully calibrated
    while being worth nothing at all.
    """
    if not args.corpus:
        print("usage: nova calibrate export <case-id> -o corpus.jsonl",
              file=sys.stderr)
        return EXIT_USAGE
    # Opened directly rather than through the scan's ``_open_store``: that one
    # reads ``--no-save`` and the other scan flags, which this command has no
    # business having. Exporting is read-only.
    from .core.store import CaseStore

    store = CaseStore(getattr(args, "case_dir", None) or None)
    try:
        graph = store.graph(args.corpus)
    except Exception as exc:                            # noqa: BLE001
        print(f"cannot read case {args.corpus}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    finally:
        store.close()

    rows: list[dict[str, Any]] = []
    for edge in graph.edges.values():
        hub = max(graph.degree(edge.src), graph.degree(edge.dst))
        rows.append({
            "id": f"{args.corpus}:{edge.src}->{edge.dst}:{edge.label}",
            "label": None,
            "hub_degree": hub,
            "basis": "",
            "note": f"{edge.src} -> {edge.dst} ({edge.label}), "
                    f"NOVA said {edge.probability:.0%} / {edge.grade}",
            "observations": [
                {k: v for k, v in (
                    ("kind", o.kind), ("module", o.module), ("url", o.url),
                    ("group", o.group),
                    ("age_days", None if o.age_days is None
                     else round(o.age_days, 1))) if v not in (None, "")}
                for o in edge.observations],
        })
    if not rows:
        print(f"case {args.corpus} drew no edges", file=sys.stderr)
        return EXIT_NO_FINDINGS

    out = Path(args.out or f"{args.corpus}-corpus.jsonl")
    body = "\n".join(json.dumps(r, sort_keys=True) for r in rows)
    out.write_text(
        '# nova calibration corpus. Set "label" to true or false on every row\n'
        '# whose truth you can vouch for, and delete the rest. Put how you\n'
        '# established it in "basis" - an unsourced label calibrates nothing\n'
        '# but the adjudicator. Then: nova calibrate report ' + out.name + "\n"
        + body + "\n", encoding="utf-8")
    print(f"wrote {len(rows)} unlabelled row(s) to {out}")
    print('Set "label": true or false on the ones you can vouch for, then:')
    print(f"  nova calibrate report {out}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# measuring the measuring instrument
# ---------------------------------------------------------------------------

#: The synthetic corpus is generated from a *stated* model: each case draws
#: evidence kinds, the true log-odds are the table's own values, and the label
#: is sampled from that. So a correct harness must come back saying the table
#: is well calibrated - and a harness with a sign error, a double-counted
#: discount or a broken hub divisor will not.
_SELFTEST_KINDS = ("cert-san", "dns-a", "handle-unverified", "tracker-id-shared",
                   "whois-email", "name-similarity", "profile-link", "commit-email")


def _synthesise(n: int, seed: int, *, distort: float = 1.0) -> list[Case]:
    import math

    from .core.graph import EVIDENCE

    rng = random.Random(seed)
    cases: list[Case] = []
    for i in range(n):
        picked = rng.sample(_SELFTEST_KINDS, rng.randint(1, 3))
        obs = tuple(ObservationSpec(kind=k, module=f"m{j}",
                                    url=f"https://s{j}.test/{i}")
                    for j, k in enumerate(picked))
        hub = rng.choice([0, 0, 0, 4, 30, 200])
        llr = sum(EVIDENCE[k] for k in picked) * distort
        if hub > 2 and llr > 0:
            llr /= 1.0 + math.log(hub / 2.0)
        p = 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, llr))))
        cases.append(Case(id=f"syn-{seed}-{i}", label=rng.random() < p,
                          observations=obs, hub_degree=hub,
                          basis="synthetic: sampled from the table itself"))
    return cases


def _selftest(args: argparse.Namespace) -> int:
    """Does the harness notice a table that is right, and one that is wrong?

    A calibration report is only worth reading if the thing producing it has
    itself been checked, and the check is cheap: generate cases *from* the
    table, and the report must say the table is calibrated. Then generate cases
    from a table inflated by 60% and the report must say it is not.
    """
    print("selftest: the harness, measured against ground truth it cannot see\n")
    honest = evaluate(_synthesise(1500, seed=7))
    print(f"  cases drawn from the table itself:")
    print(f"    calibration error {honest.ece:.3f}   skill {honest.skill:+.3f}"
          f"   AUC {honest.auc:.3f}")
    ok_honest = honest.ece <= 0.06 and honest.skill > 0.15
    print(f"    -> {'as expected: reads as calibrated' if ok_honest else 'FAILED: a table generating its own cases must read as calibrated'}")

    print()
    # Cases generated from *weaker* truth than the table claims: NOVA should
    # then be visibly over-confident, which is the failure that matters most.
    over = evaluate(_synthesise(1500, seed=11, distort=0.45))
    high = [b for b in over.bins if b.count and b.low >= 0.6]
    gap = (sum(b.predicted - b.observed for b in high) / len(high)) if high else 0.0
    print("  cases where the evidence is really worth less than the table says:")
    print(f"    calibration error {over.ece:.3f}   "
          f"over-confidence above 60%: {gap:+.2f}")
    ok_over = over.ece > honest.ece and gap > 0.05
    print(f"    -> {'as expected: the over-confidence is detected' if ok_over else 'FAILED: over-confidence went unnoticed'}")

    print()
    worse = [s for s in over.suggestions if s.fitted is not None and s.shift < 0]
    print(f"  weights the fit pulled down: {len(worse)} of "
          f"{sum(1 for s in over.suggestions if s.fitted is not None)}")
    ok_fit = len(worse) >= 3
    print(f"    -> {'as expected: the fit moves in the right direction' if ok_fit else 'FAILED: the fit did not lower inflated weights'}")

    print()
    if ok_honest and ok_over and ok_fit:
        print("selftest passed. The harness detects both a calibrated table "
              "and an inflated one.")
        return EXIT_OK
    print("selftest FAILED - do not trust a calibration report from this build.",
          file=sys.stderr)
    return EXIT_NO_FINDINGS
