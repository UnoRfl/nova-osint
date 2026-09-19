"""``nova investigate`` and ``nova browser``: the two commands added by the
free-first investigation layer.

Kept out of ``cli.py`` deliberately. That file is already the longest thing in
the project and its job is argument parsing and precedence; putting a second
orchestration flow in it would bury the one rule that file exists to enforce -
that a flag left unset is ``None`` and does not overwrite ``config.json``.
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import Any

from .core import report as reporting
from .core.browser import BrowserOptions, available_backends, open_browser
from .core.investigate import investigate as run_investigation
from .core.investigate import plan_for
from .core.models import Severity, TargetType
from .core.registry import detect_type

EXIT_OK = 0
EXIT_NO_FINDINGS = 1
EXIT_USAGE = 2


def add_parsers(sub: Any, common: Any, search_flags: Any) -> None:
    """Register both commands on the main parser."""
    inv = sub.add_parser(
        "investigate",
        help="work out what to ask, ask it, follow what it finds",
        description="Give it a name, a handle, an address, a domain or an IP. "
                    "It plans the queries, runs the free sources, follows what "
                    "they imply, and says what it could not reach.",
    )
    inv.add_argument("target", nargs="?",
                     help="a name, username, email, domain, IP, phone or URL")
    inv.add_argument("-K", "--know", action="append", default=[], metavar="FACT=VALUE",
                     help="something you already know about the subject; "
                          "repeatable, and the single most useful thing you can "
                          "give it")
    inv.add_argument("--brief", metavar="FILE",
                     help="read the same facts from a JSON or YAML file")
    inv.add_argument("--subject", choices=("person", "org"), default="person")
    inv.add_argument("-t", "--type", choices=[t.value for t in TargetType
                                              if t is not TargetType.UNKNOWN])
    inv.add_argument("-o", "--output")
    inv.add_argument("-f", "--format", default="console",
                     choices=sorted(reporting.RENDERERS))
    inv.add_argument("--depth", type=int, default=None,
                     help="1 direct, 2 first-order pivots, 3 second-order, "
                          "4 deep correlation (default 2)")
    inv.add_argument("--budget", choices=("quick", "normal", "deep"), default="normal")
    inv.add_argument("--max-entities", type=int, default=None)
    inv.add_argument("--time-limit", type=float, default=None, metavar="SECONDS")
    inv.add_argument("--max-queries", type=int, default=8,
                     help="how many planned queries to run (default 8)")
    inv.add_argument("--browser", action="store_true",
                     help="use your own browser for what plain HTTP cannot "
                          "reach. Nothing is bypassed: a login wall or a "
                          "CAPTCHA is reported for you to finish yourself")
    inv.add_argument("--browser-show", action="store_true",
                     help="run the browser visibly instead of headless")
    inv.add_argument("--browser-profile", default="",
                     help="a browser profile directory to reuse (default: a "
                          "throwaway profile, deleted afterwards)")
    inv.add_argument("--assist", action="store_true",
                     help="let a local model suggest what to ask next; it "
                          "never produces findings (see `nova assist status`)")
    inv.add_argument("--assist-url", default=None,
                     help="where the model server is (default "
                          "http://127.0.0.1:11434)")
    inv.add_argument("--assist-model", default=None, metavar="NAME")
    inv.add_argument("--assist-provider", default=None,
                     choices=("ollama", "openai"))
    inv.add_argument("--assist-allow-remote", action="store_true",
                     help="permit a model server outside this machine or "
                          "network. It discloses the investigation and may "
                          "cost money; refused by default.")
    inv.add_argument("--image", action="append", default=[], metavar="FILE",
                     help="a photograph to read for clues (EXIF, text, logos)")
    inv.add_argument("--dry-run", action="store_true",
                     help="print the plan and stop without asking anything")
    inv.add_argument("--only")
    inv.add_argument("--exclude")
    inv.add_argument("--passive", action="store_true")
    inv.add_argument("--allow-paid", action="store_true",
                     help="permit sources that cost money (off by default)")
    inv.add_argument("--redact", action="store_true")
    inv.add_argument("--redact-salt", default="")
    inv.add_argument("--no-save", action="store_true")
    inv.add_argument("--label", default="")
    inv.add_argument("--min-severity", choices=[s.value for s in Severity],
                     default="info")
    inv.add_argument("-q", "--quiet", action="store_true")
    inv.add_argument("--no-art", action="store_true")
    inv.add_argument("--max-sites", type=int, default=None)
    inv.add_argument("--no-verify", action="store_false", dest="verify")
    inv.set_defaults(verify=True, refresh_sites=False, include_nsfw=False,
                     expand=True, pivot=False, pivot_limit=0)
    search_flags(inv)
    common(inv)

    img = sub.add_parser("image",
                         help="read one image for clues, locally and offline")
    img.add_argument("path", nargs="+", help="image file(s) to read")
    img.add_argument("--no-ocr", action="store_true",
                     help="skip text extraction")
    img.add_argument("--compare", action="store_true",
                     help="report how similar the supplied images are")
    img.add_argument("-f", "--format", choices=("text", "json"), default="text")
    common(img)

    br = sub.add_parser("browser",
                        help="check or set up the browser NOVA can drive")
    br.add_argument("action", nargs="?", default="status",
                    choices=("status", "setup", "test"))
    br.add_argument("--url", default="https://example.com",
                    help="page to load for `browser test`")
    br.add_argument("--show", action="store_true", help="run visibly")
    br.add_argument("--profile", default="")
    common(br)

    asi = sub.add_parser(
        "assist",
        help="check the optional local model that suggests what to ask next")
    asi.add_argument("action", nargs="?", default="status",
                     choices=("status", "test"))
    asi.add_argument("--assist-url", default=None)
    asi.add_argument("--assist-model", default=None)
    asi.add_argument("--assist-provider", default=None,
                     choices=("ollama", "openai"))
    common(asi)


# ---------------------------------------------------------------------- assist


def _assist_settings(args: argparse.Namespace, cfg: Any) -> Any:
    """Flag over env over config.json over default, same as every other flag.

    Every ``--assist-*`` option defaults to ``None`` so an unset flag cannot
    overwrite a value the operator put in ``config.json`` - the one rule
    ``cli.py`` exists to enforce, and the one a new flag quietly breaks.
    """
    from .core.assist import AssistSettings

    settings = AssistSettings.from_config(cfg)
    if getattr(args, "assist", False):
        settings.enabled = True
    for flag, field in (("assist_url", "base_url"), ("assist_model", "model"),
                        ("assist_provider", "provider")):
        value = getattr(args, flag, None)
        if value:
            setattr(settings, field, value.rstrip("/") if field == "base_url"
                    else value)
    if getattr(args, "assist_allow_remote", False):
        settings.allow_remote = True
    return settings


def _print_assist(outcome: Any) -> None:
    """Show the model's suggestions, fenced off from everything it is not.

    Printed under its own heading, with the word *hypothesis* on every line and
    the sentence that says what these are. The section exists to be read by
    somebody scrolling fast, and somebody scrolling fast must not be able to
    mistake a machine's guess for a source's statement.
    """
    if outcome is None or not (outcome.questions or outcome.hypotheses
                               or outcome.discarded):
        return
    out = sys.stderr
    print("LOCAL MODEL - suggestions only. Nothing here is evidence, and "
          "nothing here\nentered the graph. Every question below was run and "
          "is evidenced by\nwhatever answered it, not by having been "
          "suggested.\n", file=out)
    if outcome.questions:
        print("  questions it would ask next:", file=out)
        for q in outcome.questions:
            print(f"    - {q.query}", file=out)
            if q.why:
                print(f"        {q.why}", file=out)
    if outcome.hypotheses:
        print("\n  hypotheses (unverified readings of the evidence):", file=out)
        for h in outcome.hypotheses:
            print(f"    - {h.claim}", file=out)
            print(f"        rests on: {', '.join(h.supports)}", file=out)
            if h.confirm_with:
                print(f"        confirm by: {h.confirm_with}", file=out)
            if h.refute_with:
                print(f"        refute by: {h.refute_with}", file=out)
    if outcome.discarded:
        print(f"\n  discarded {len(outcome.discarded)} by the citation check:",
              file=out)
        for why in outcome.discarded[:5]:
            print(f"    - {why}", file=out)
    print(file=out)


def cmd_assist(args: argparse.Namespace, cfg: Any) -> int:
    """Say whether a model is reachable, and prove it end to end."""
    from .core.assist import Assistant, validate

    settings = _assist_settings(args, cfg)
    settings.enabled = True
    local, where = settings.locality()
    print(f"provider : {settings.provider}")
    print(f"endpoint : {settings.base_url}  ({where})")
    print(f"model    : {settings.model}")

    # Through the Engine rather than a bare Fetcher, so the endpoint is
    # contacted with the same timeouts, proxy and TLS settings as everything
    # else the operator configured.
    from .core.engine import Engine

    engine = Engine(cfg)
    http = engine.http
    try:
        client = Assistant(http, settings)
        ok, why = client.check()
        print(f"status   : {'ready' if ok else 'unavailable'} - {why}")
        if not ok:
            print("\nNOVA runs fine without it; every stage that would have "
                  "used it\nsays so instead. To add one, free and local:\n"
                  "  1. install Ollama from https://ollama.com/download\n"
                  f"  2. ollama pull {settings.model}\n"
                  "  3. nova assist test\n"
                  "\nAnything OpenAI-compatible works too "
                  "(--assist-provider openai).")
            return EXIT_NO_FINDINGS
        if args.action != "test":
            print("\nIt suggests questions and hypotheses only. Nothing it says "
                  "enters\nthe evidence graph, and a hypothesis citing an entity "
                  "that does not\nexist is discarded.")
            return EXIT_OK

        started = time.monotonic()
        text, error = client.ask(
            "SUBJECT: example.com\n\nENTITIES (id | kind | relevance | "
            "independent sources):\n  domain:example.com | domain | 1.000 | 1\n"
            "  email:webmaster@example.com | email | 0.412 | 2\n\n"
            "GAPS AND UNFOLLOWED LEADS:\n  whois: skipped - needs a key\n")
        if error:
            print(f"\ntest     : FAILED - {error}", file=sys.stderr)
            return EXIT_NO_FINDINGS
        got = validate(text, {"domain:example.com", "email:webmaster@example.com"})
        print(f"\ntest     : ok in {time.monotonic() - started:.1f}s")
        print(f"questions: {len(got.questions)}")
        for q in got.questions:
            print(f"  - {q.query}")
        print(f"hypotheses: {len(got.hypotheses)}")
        for h in got.hypotheses:
            print(f"  - {h.claim}  [cites {', '.join(h.supports)}]")
        if got.discarded:
            print(f"discarded: {len(got.discarded)}")
            for d in got.discarded:
                print(f"  - {d}")
        return EXIT_OK
    finally:
        engine.close()


# --------------------------------------------------------------------- browser


def cmd_browser(args: argparse.Namespace, cfg: Any) -> int:
    backends = available_backends()
    if args.action == "status":
        print("browser backends available: "
              + (", ".join(backends) if backends else "none"))
        if not backends:
            print("\nNOVA works without one - it will say so wherever a browser "
                  "would have helped.\nTo add one:\n"
                  "  pip install playwright\n"
                  "  playwright install chromium")
            return EXIT_NO_FINDINGS
        print("\nNOVA will use a throwaway profile unless you pass "
              "--browser-profile.\nIt never reads cookies, passwords or history "
              "from a profile you give it.")
        return EXIT_OK

    options = BrowserOptions(headless=not args.show, profile=args.profile)
    if args.action == "setup":
        if not backends:
            print("no backend installed. Run:\n  pip install playwright\n"
                  "  playwright install chromium", file=sys.stderr)
            return EXIT_NO_FINDINGS
        browser = open_browser(options)
        ok = getattr(browser, "available", False)
        print(f"backend: {browser.name}  started: {'yes' if ok else 'no'}")
        if ok and args.profile:
            print(f"profile kept at: {args.profile}")
        browser.close()
        return EXIT_OK if ok else EXIT_NO_FINDINGS

    browser = open_browser(options)
    try:
        page = browser.navigate(args.url)
        print(f"backend : {browser.name}")
        print(f"url     : {page.url}")
        print(f"status  : {page.status or '-'}")
        print(f"title   : {page.title or '-'}")
        print(f"text    : {len(page.text)} characters")
        print(f"links   : {len(page.links)}")
        if page.screenshot:
            print(f"shot    : {page.screenshot}")
        if page.human_action:
            print(f"\nHUMAN ACTION REQUIRED: {page.human_action}")
            print(f"open {page.url} yourself; NOVA will not work around it")
            return EXIT_NO_FINDINGS
        if page.error:
            print(f"\nerror: {page.error}", file=sys.stderr)
            return EXIT_NO_FINDINGS
        return EXIT_OK
    finally:
        browser.close()


# ----------------------------------------------------------------------- image


def cmd_image(args: argparse.Namespace, cfg: Any) -> int:
    """Read images locally. No network, no account, no face matching."""
    import json

    from .core.imageint import analyse, hamming

    facts = [analyse(p, do_ocr=not args.no_ocr) for p in args.path]

    if args.format == "json":
        out: dict[str, Any] = {"images": [f.to_dict() for f in facts]}
        if args.compare and len(facts) > 1:
            out["comparisons"] = _comparisons(facts, hamming)
        print(json.dumps(out, indent=2, default=str))
        return EXIT_OK if any(f.sha256 for f in facts) else EXIT_NO_FINDINGS

    for f in facts:
        print(f"\n{f.path}")
        print(f"  {f.format or 'unknown format'}  {f.width}x{f.height}"
              f"  ({f.megapixels} MP)  {f.size_bytes:,} bytes")
        print(f"  sha256   {f.sha256}")
        if f.ahash:
            print(f"  ahash    {f.ahash}    dhash {f.dhash}")
        if f.camera:
            print(f"  camera   {f.camera}")
        if f.taken_at:
            print(f"  taken    {f.taken_at}")
        if f.software:
            print(f"  software {f.software}")
        if f.gps:
            lat, lon = f.gps
            print(f"  gps      {lat}, {lon}"
                  f"   https://www.openstreetmap.org/?mlat={lat}&mlon={lon}")
        if f.text:
            first = " / ".join(line.strip() for line in f.text.splitlines()
                               if line.strip())[:300]
            print(f"  text     {first}")
        if f.clues:
            print("  clues:")
            for kind, value in f.clues[:15]:
                print(f"    {kind:<9} {value}")
        for stage, reason in f.gaps:
            print(f"  not checked: {stage} - {reason}")

    if args.compare and len(facts) > 1:
        print("\ncomparisons (bit distance; under 10 is the same picture, "
              "over 20 is a different one)")
        for row in _comparisons(facts, hamming):
            print(f"  {row['a']}  vs  {row['b']}: "
                  f"ahash {row['ahash']}, dhash {row['dhash']}  - {row['reading']}")
        print("\n  Note: this compares pictures, not people. Two photographs "
              "of one person\n  are two different pictures and will read as "
              "unrelated here.")
    return EXIT_OK if any(f.sha256 for f in facts) else EXIT_NO_FINDINGS


def _comparisons(facts: list[Any], hamming: Any) -> list[dict[str, Any]]:
    rows = []
    for i, a in enumerate(facts):
        for b in facts[i + 1:]:
            ah = hamming(a.ahash, b.ahash)
            dh = hamming(a.dhash, b.dhash)
            worst = max(ah, dh)
            reading = ("the same picture" if worst <= 10 else
                       "possibly a re-edit of the same picture" if worst <= 20
                       else "different pictures")
            if not a.ahash or not b.ahash:
                reading = "not comparable (perceptual hashing needs Pillow)"
            rows.append({"a": a.path, "b": b.path, "ahash": ah, "dhash": dh,
                         "reading": reading})
    return rows


# ----------------------------------------------------------------- investigate


def cmd_investigate(args: argparse.Namespace, manager: Any, cfg: Any,
                    build_brief: Any, budget_for: Any, open_store: Any,
                    save_case: Any, resolve_output: Any) -> int:
    """The headline command. Dependencies are passed in rather than imported
    so this module does not import ``cli`` and create a cycle."""
    from .core import brief as briefing

    try:
        brief = build_brief(args)
    except briefing.BriefError as exc:
        print(exc, file=sys.stderr)
        return EXIT_USAGE

    if not args.target:
        seeds = brief.seeds if brief else []
        if not seeds:
            print("give something to investigate, for example:\n"
                  "  nova investigate \"Ada Lovelace\"\n"
                  "  nova investigate ada@example.org\n"
                  "  nova investigate -K name='Ada Lovelace' -K employer=Acme",
                  file=sys.stderr)
            return EXIT_USAGE
        args.target = seeds[0].value
        args.type = args.type or briefing.SEEDABLE[seeds[0].kind].value

    ttype = TargetType(args.type) if args.type else detect_type(args.target)
    if ttype is TargetType.UNKNOWN:
        print(f"could not work out what {args.target!r} is; pass --type",
              file=sys.stderr)
        return EXIT_USAGE

    if args.allow_paid:
        cfg.set_option("allow_paid", True)

    budget = budget_for(args)
    if args.time_limit:
        budget.max_seconds = float(args.time_limit)

    plan, _ = plan_for(args.target, cfg, target_type=ttype, brief=brief,
                       max_queries=max(0, args.max_queries))
    if args.dry_run:
        print(f"target: {args.target}  ({ttype.value})")
        print(f"budget: depth {budget.max_depth}, {budget.max_entities} entities, "
              f"{budget.max_seconds:.0f}s")
        print(f"\n{len(plan.queries)} quer{'y' if len(plan.queries) == 1 else 'ies'}, "
              "most identifying first:")
        for q in plan.queries:
            mark = "  (ambiguous - may be about anyone with this name)" \
                if q.ambiguous else ""
            print(f"  {q.value:>5.2f}  [{q.category.label}] {q.text}{mark}")
            print(f"         {q.rationale}")
        return EXIT_OK

    browser = None
    if args.browser:
        browser = open_browser(BrowserOptions(headless=not args.browser_show,
                                              profile=args.browser_profile))
        if not getattr(browser, "available", False) and not args.quiet:
            print("no browser backend started; continuing without one "
                  "(run: nova browser status)", file=sys.stderr)

    store = open_store(args)
    evidence = store.evidence if store is not None else None
    started = time.time()
    last: list[str] = []

    def on_progress(stages: Any) -> None:
        if args.quiet or not sys.stderr.isatty():
            return
        text = "  ".join(s.name for s in stages if s.state == "running")
        if text and text not in last:
            last.append(text)
            print(f"\r  {text} …", end="", file=sys.stderr, flush=True)

    try:
        report = run_investigation(
            args.target, cfg, target_type=ttype, brief=brief if len(brief) > 1 else None,
            budget=budget, browser=browser, evidence=evidence,
            only=args.only.split(",") if args.only else None,
            exclude=args.exclude.split(",") if args.exclude else None,
            on_progress=on_progress, max_queries=max(0, args.max_queries),
            images=list(args.image or []), assist=_assist_settings(args, cfg),
        )
    finally:
        if browser is not None:
            browser.close()

    if not args.quiet and sys.stderr.isatty():
        print("\r" + " " * 60 + "\r", end="", file=sys.stderr)

    inv = report.investigation
    case_id = save_case(store, args, inv)
    if store is not None:
        store.close()

    if not args.quiet:
        print(report.tree(), file=sys.stderr)
        print(file=sys.stderr)
        _print_assist(report.assist)

    rendered = inv
    if args.redact:
        from .core.graphview import Redactor, redact_investigation

        redactor = Redactor(True, args.redact_salt)
        rendered = redact_investigation(inv, redactor)

    if args.format == "console":
        out = reporting.render_console(rendered, verbose=args.verbose > 0,
                                       min_severity=Severity(args.min_severity))
    elif args.format == "json":
        out = reporting.render_json(rendered)
    else:
        out = reporting.RENDERERS[args.format](rendered)

    if case_id and not args.quiet:
        print(case_id, file=sys.stderr)

    if args.output:
        destination = resolve_output(args.output, cfg)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(out, "utf-8")
        print(f"wrote {destination}  ({len(inv.findings)} findings, "
              f"{time.time() - started:.1f}s)", file=sys.stderr)
    else:
        sys.stdout.write(out if out.endswith("\n") else out + "\n")

    return EXIT_OK if inv.findings else EXIT_NO_FINDINGS
