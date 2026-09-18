"""Command line interface.

Argument defaults are deliberately ``None`` rather than real numbers. ``None``
means "the user did not say", which lets the precedence chain work::

    flag  >  environment  >  config.json  >  built-in default

If ``--timeout`` defaulted to ``12.0`` there would be no way to tell a user who
typed ``--timeout 12`` from one who typed nothing, and ``config.json`` could
never win.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from pathlib import Path

from .core import art
from .core import brief as briefing
from .core import report as reporting
from .core.config import (
    DEFAULT_CACHE,
    DEFAULT_CONFIG_PATH,
    KEY_ENV,
    Config,
    ConfigManager,
    load_env_file,
)
from .core.engine import Engine
from .core.logging_config import get_logger, setup_logging
from .core.models import Severity, TargetType
from .core.registry import all_modules, detect_type
from .core.search import ENGINE_MODES

log = get_logger("cli")

LEGAL = """\
NOVA queries public sources only. You are responsible for using it
lawfully: have authorisation for the target, respect each source's terms, and
remember that "publicly available" is not the same as "fair to aggregate".
Scanning people or infrastructure you have no relationship with can be illegal
where you are.

NOVA identifies itself honestly in every request and does not attempt to work
around rate limits, CAPTCHAs, bot detection, authentication or access controls.
When a source refuses, that refusal is recorded in the report and the scan
moves on.
"""

#: Exit codes, so the tool composes in a shell script.
EXIT_OK = 0            # scan completed, findings present
EXIT_NO_FINDINGS = 1   # scan completed, nothing found
EXIT_USAGE = 2         # bad target or bad arguments
EXIT_NOTHING_RAN = 3   # every module was skipped or filtered out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nova",
        description="NOVA - all-in-one OSINT collection across public sources.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  nova doctor                                  can this machine reach the sources?
  nova scan example.com
  nova scan example.com --expand               follow what it connects to
  nova scan example.com --expand -f graph -o graph.html
  nova scan alice@example.com --redact -f html -o share.html
  nova phone "+44 20 7946 0958"                 caller-ID style card
  nova scan "Ada Lovelace"                     search by name
  nova scan someuser --only username,keys,keybase
  nova scan example.com --passive --quiet --format json

  nova history                                 every saved case
  nova diff example.com                        what changed since last time
  nova show <case>                             one case in full
  nova link <case-a> <case-b>                  what two investigations share
  nova where alice@example.com                 which cases have seen this
  nova replay <case>                           re-derive it from stored evidence
  nova evidence <case>                         verify that evidence still hashes

  nova modules
  nova config show
""",
    )
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="run a scan against one target")
    scan.add_argument("target", nargs="?", default=None,
                      help="domain, email, username, IP, phone number or URL. "
                           "Optional when the whole subject is given with --know")
    # The brief. Everything the user already knows: extra seeds to scan from,
    # and - the part that matters - the evidence that tells the results apart.
    scan.add_argument("-K", "--know", action="append", default=[], metavar="FACT=VALUE",
                      help="something you already know about the subject, e.g. "
                           "-K city='Kuala Lumpur' -K employer=Acme -K dob=1971. "
                           "Repeatable. A '?' on the key ("
                           "-K 'city?=KL') marks it uncertain, so it is still "
                           "tested but cannot bury a candidate on its own")
    scan.add_argument("--brief", metavar="FILE",
                      help="read the same facts from a JSON or YAML file")
    scan.add_argument("--subject", choices=["person", "org"], default="person",
                      help="what the subject is (default: person)")
    scan.add_argument("-t", "--type", choices=[t.value for t in TargetType if t != TargetType.UNKNOWN],
                      help="force the target type instead of auto-detecting")
    scan.add_argument("-o", "--output", type=Path,
                      help="write the report to a file (a bare filename lands in "
                           "settings.output_directory)")
    scan.add_argument("-f", "--format", choices=sorted(reporting.RENDERERS),
                      default="console", help="output format (default: console)")
    scan.add_argument("--only", help="comma-separated module names to run exclusively")
    scan.add_argument("--exclude", help="comma-separated module names to skip")
    scan.add_argument("--passive", action="store_true", default=None,
                      help="never touch the target's own infrastructure")
    scan.add_argument("--expand", action="store_true",
                      help="keep going: scan whatever the target connects to, "
                           "best-evidenced leads first")
    scan.add_argument("--budget", choices=["quick", "normal", "deep"], default="normal",
                      help="how much an --expand walk may spend (default: normal)")
    scan.add_argument("--depth", type=int, default=None,
                      help="override the expansion depth limit")
    scan.add_argument("--max-entities", type=int, default=None,
                      help="override the expansion entity cap")
    scan.add_argument("--no-save", action="store_true",
                      help="do not record this scan in the case store")
    scan.add_argument("--label", default="", help="a note stored with the case")
    scan.add_argument("--redact", action="store_true",
                      help="mask emails, handles and phone numbers in the OUTPUT "
                           "(the case store still keeps the real values)")
    scan.add_argument("--redact-salt", default="",
                      help="reuse a salt so two redacted reports use the same tokens")
    scan.add_argument("--pivot", action="store_true",
                      help="also scan discovered IPs, emails and usernames (one level deep)")
    scan.add_argument("--pivot-limit", type=int, default=5, help="max pivots to follow")
    # Measured on a 45-site sample with a handle nobody owns: 7 false positives
    # without verification, 0 with it. That is worth one extra request per hit.
    scan.add_argument("--no-verify", action="store_false", dest="verify",
                      help="skip the control-handle re-test on username hits "
                           "(faster, but soft-404 sites will show up as hits)")
    scan.set_defaults(verify=True)
    scan.add_argument("--refresh-sites", action="store_true",
                      help="re-download the username site database")
    scan.add_argument("--include-nsfw", action="store_true",
                      help="include adult platforms in username results")
    scan.add_argument("--max-sites", type=int, default=None,
                      help="cap the number of sites / subdomains probed (0 = no cap)")
    scan.add_argument("--min-severity", choices=[s.value for s in Severity], default="info",
                      help="hide findings below this interest level")
    _search_flags(scan)
    scan.add_argument("-q", "--quiet", action="store_true", help="no banner, no progress")
    scan.add_argument("--no-art", action="store_true", help="keep the progress line, drop the ASCII art")
    _common(scan)

    from .investigation_cli import add_parsers as _investigation_parsers

    _investigation_parsers(sub, _common, _search_flags)

    mods = sub.add_parser("modules", help="list available modules")
    mods.add_argument("-t", "--type", choices=[t.value for t in TargetType],
                      help="only modules that accept this target type")
    _common(mods)

    hist = sub.add_parser("history", help="list saved cases")
    hist.add_argument("target", nargs="?", help="only cases for this target")
    hist.add_argument("-n", "--limit", type=int, default=25, help="how many to list")
    hist.add_argument("-f", "--format", choices=["text", "json"], default="text")
    _common(hist)

    show = sub.add_parser("show", help="print a saved case")
    show.add_argument("case", help="case id, or an unambiguous prefix of one")
    show.add_argument("-n", "--limit", type=int, default=20,
                      help="how many entities to list")
    show.add_argument("-f", "--format", choices=["text", "json"], default="text")
    _common(show)

    dif = sub.add_parser("diff", help="what changed between two scans")
    dif.add_argument("old", help="older case id, or a target to compare its last two runs")
    dif.add_argument("new", nargs="?", help="newer case id")
    dif.add_argument("-f", "--format", choices=["text", "json"], default="text")
    _common(dif)

    lnk = sub.add_parser("link", help="entities two saved cases have in common")
    lnk.add_argument("case_a")
    lnk.add_argument("case_b")
    lnk.add_argument("-f", "--format", choices=["text", "json"], default="text")
    _common(lnk)

    whr = sub.add_parser("where", help="which saved cases have seen this value")
    whr.add_argument("value")
    whr.add_argument("-t", "--type", help="entity type, if the guess is wrong")
    _common(whr)

    rep = sub.add_parser("replay", help="re-derive a case from its stored evidence")
    rep.add_argument("case")
    rep.add_argument("-f", "--format", choices=["text", "json"], default="text")
    _common(rep)

    evi = sub.add_parser("evidence", help="verify stored evidence, or print one blob")
    evi.add_argument("case", nargs="?", help="limit the check to one case")
    evi.add_argument("--digest", help="print this blob to stdout instead")
    _common(evi)

    ph = sub.add_parser("phone", help="identify one phone number, caller-ID style")
    ph.add_argument("number", help="the number, ideally in +CC... form")
    ph.add_argument("-f", "--format", choices=["card", "json"], default="card")
    ph.add_argument("-o", "--output", type=Path, help="also write the card here")
    _common(ph)

    doc = sub.add_parser("doctor", help="probe every source from this machine")
    doc.add_argument("--keyless", action="store_true",
                     help="skip sources that need an API key")
    doc.add_argument("--leak-check", action="store_true",
                     help="check that --proxy actually changes the address we "
                          "present, instead of silently falling back to direct")
    doc.add_argument("-f", "--format", choices=["text", "json"], default="text")
    _common(doc)

    cfg = sub.add_parser("config", help="show, create or locate the configuration file")
    cfg.add_argument("action", nargs="?", default="show", choices=["show", "init", "path"],
                     help="show (default, API keys masked), init, or path")
    _common(cfg)

    sub.add_parser("legal", help="print the usage and legal notice")
    sub.add_parser("art", help="show every banner NOVA can draw")
    sub.add_parser("gui", help="open the desktop app")
    return p


def _search_flags(sp: argparse.ArgumentParser) -> None:
    """Which free search engines this run may use, and how far it may go.

    Split out because ``scan`` and ``investigate`` both take them and a
    divergence between the two would mean the same flag doing different things
    in the two commands people use interchangeably.
    """
    grp = sp.add_argument_group("search")
    grp.add_argument("--search-engine", default=None,
                     choices=list(ENGINE_MODES),
                     help="auto: the best free engine that answers; api: only "
                          "documented endpoints; page: only human result pages; "
                          "browser: only through your own browser; all: every "
                          "available engine, merged (default: auto)")
    grp.add_argument("--serp-pages", action="store_true", default=None,
                     help="allow reading search-engine result pages built for "
                          "people (Mojeek, DuckDuckGo Lite). Off by default: "
                          "fetchable and offered-to-programs are not the same "
                          "thing, and NOVA does not pretend otherwise")
    grp.add_argument("--search-queries", type=int, default=None,
                     help="how many planned queries one scan may run (default 6)")
    grp.add_argument("--searxng", default=None, metavar="URL",
                     help="a SearXNG instance you are entitled to use, e.g. "
                          "http://localhost:8888")
    grp.add_argument("--no-search", action="store_true",
                     help="run no search engines at all")


def _common(sp: argparse.ArgumentParser) -> None:
    """Flags every subcommand shares. All default to ``None`` - see the module docstring."""
    g = sp.add_argument_group("network")
    g.add_argument("--timeout", type=float, default=None, help="per-request timeout (s)")
    g.add_argument("--concurrency", type=int, default=None, help="parallel requests")
    g.add_argument("--delay", type=float, default=None, dest="per_host_delay",
                   help="minimum seconds between requests to the same host")
    g.add_argument("--retries", type=int, default=None, help="retries on 429/503/timeouts")
    g.add_argument("--proxy", help="http(s) proxy, e.g. http://127.0.0.1:8080")
    g.add_argument("--user-agent", help="override the User-Agent header")
    g.add_argument("--insecure", action="store_true", dest="insecure",
                   help="do not verify TLS certificates")
    g.add_argument("--no-cache", action="store_true", help="bypass the on-disk response cache")
    g.add_argument("--cache-ttl", type=float, default=None, help="cache lifetime (s)")
    g.add_argument("--env-file", type=Path, help="load API keys from this KEY=value file")

    d = sp.add_argument_group("diagnostics")
    d.add_argument("-c", "--config", type=Path, default=None,
                   help=f"configuration file (default: {DEFAULT_CONFIG_PATH})")
    d.add_argument("-v", "--verbose", action="count", default=0,
                   help="-v for progress logging, -vv for debug")
    d.add_argument("--case-dir", type=Path, default=None,
                   help="where cases, evidence and the audit log live")
    d.add_argument("--log-file", type=Path, default=None,
                   help="also write a full debug log here (API keys are redacted)")


def load_config(args: argparse.Namespace) -> tuple[ConfigManager, Config]:
    """Resolve logging, the config file and the command-line overrides.

    Returns the manager (so callers can show problems or the file path) and the
    :class:`Config` that a scan will actually run with.
    """
    setup_logging(getattr(args, "verbose", 0), getattr(args, "log_file", None))

    if getattr(args, "env_file", None):
        try:
            n = load_env_file(args.env_file)
            log.info("loaded %d key(s) from %s", n, args.env_file)
        except FileNotFoundError:
            log.error("env file not found: %s", args.env_file)

    manager = ConfigManager(getattr(args, "config", None)).load()

    cache_dir = None if getattr(args, "no_cache", False) else DEFAULT_CACHE / "http"
    cfg = manager.to_config(
        timeout=args.timeout,
        concurrency=args.concurrency,
        per_host_delay=args.per_host_delay,
        retries=args.retries,
        proxy=args.proxy,
        user_agent=args.user_agent,
        verify_tls=False if args.insecure else None,
        cache_ttl=args.cache_ttl,
        cache_dir=cache_dir,
        passive_only=getattr(args, "passive", None),
        max_sites=getattr(args, "max_sites", None),
    )
    # Module-local switches ride on the config rather than widening every
    # module signature for options only one module cares about.
    cfg.set_option("verify_hits", getattr(args, "verify", False))
    cfg.set_option("refresh_sites", getattr(args, "refresh_sites", False))
    cfg.set_option("include_nsfw", getattr(args, "include_nsfw", False))

    # Search options follow the same precedence rule as everything else: a
    # flag left unset is None and does not overwrite config.json.
    if getattr(args, "no_search", False):
        cfg.set_option("search_engine", "none")
    elif getattr(args, "search_engine", None):
        cfg.set_option("search_engine", args.search_engine)
    if getattr(args, "serp_pages", None):
        cfg.set_option("allow_serp_pages", True)
    if getattr(args, "search_queries", None) is not None:
        cfg.set_option("search_queries", max(0, int(args.search_queries)))
    if getattr(args, "searxng", None):
        cfg.set_option("searxng_url", args.searxng)

    for problem in manager.problems:
        log.warning("config: %s", problem)
    return manager, cfg


class Progress:
    """A one-line satellite that orbits while the instruments report back."""

    FRAMES = art.SPINNER

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled and sys.stderr.isatty()
        self.active: set[str] = set()
        self.done = 0
        self.lock = threading.Lock()
        self.tick = 0

    def __call__(self, module: str, state: str) -> None:
        if not self.enabled:
            return
        with self.lock:
            if state == "start":
                self.active.add(module)
            else:
                self.active.discard(module)
                self.done += 1
            self.tick += 1
            running = " ".join(
                f"{art.glyph(m)} {m}" for m in sorted(self.active)[:4]
            ) or "closing the shutter"
            frame = self.FRAMES[self.tick % len(self.FRAMES)]
            line = f"\r {frame}  {self.done} instruments in   {running}"
            sys.stderr.write(line[:110].ljust(112))
            sys.stderr.flush()

    def clear(self) -> None:
        if self.enabled:
            sys.stderr.write("\r" + " " * 112 + "\r")
            sys.stderr.flush()


def cmd_modules(args: argparse.Namespace) -> int:
    _, cfg = load_config(args)
    wanted = TargetType(args.type) if args.type else None
    rows = []
    for cls in all_modules():
        if wanted and wanted not in cls.accepts:
            continue
        need = cls.requires_key
        status = "ready"
        if need and not cfg.has(need):
            status = f"needs ${KEY_ENV.get(need, need)}"
        elif cls.name in cfg.disabled_modules:
            status = "disabled in config.json"
        rows.append((cls.name, ",".join(sorted(t.value for t in cls.accepts)),
                     "active" if cls.active else "passive", status, cls.description))

    width = max((len(r[0]) for r in rows), default=8)
    print(f"{'MODULE'.ljust(width)}  {'ACCEPTS'.ljust(28)}  {'MODE'.ljust(8)}  STATUS")
    print("-" * 110)
    for name, accepts, mode, status, desc in rows:
        print(f"{name.ljust(width)}  {accepts[:28].ljust(28)}  {mode.ljust(8)}  {status}")
        print(f"{' ' * width}  {desc}")
    print(f"\n{len(rows)} module(s). Keys are read from the environment: "
          f"{', '.join(sorted(KEY_ENV.values()))}")
    return EXIT_OK


def cmd_config(args: argparse.Namespace) -> int:
    # Checked before load_config, which creates the file if it is missing -
    # otherwise `config init` could only ever report "already exists".
    existed = (args.config or DEFAULT_CONFIG_PATH).exists()
    manager, _ = load_config(args)
    if args.action == "path":
        print(manager.path)
        return EXIT_OK
    if args.action == "init":
        if existed:
            print(f"{manager.path} already exists; leaving it alone", file=sys.stderr)
        else:
            manager.write_default()
            print(f"wrote {manager.path}", file=sys.stderr)
        return EXIT_OK
    # show - always redacted, because this output ends up pasted into issues.
    print(json.dumps(manager.redacted(), indent=4))
    print(f"\n# file: {manager.path}"
          f"\n# loaded from disk: {'yes' if manager.loaded_from_file else 'no (defaults)'}",
          file=sys.stderr)
    for problem in manager.problems:
        print(f"# problem: {problem}", file=sys.stderr)
    return EXIT_OK


def _resolve_output(path: Path, cfg: Config) -> Path:
    """A bare filename goes to ``settings.output_directory``; a path is obeyed."""
    if path.parent == Path("."):
        return cfg.output_dir / path
    return path


def _build_brief(args: argparse.Namespace):
    """Assemble the brief from --brief, --know and the positional target.

    The positional target is folded in as a claim of its own, because it *is*
    one: a user who types an address and then adds a city has told NOVA two
    things about one person, and the resolver has to see both or the address -
    the strongest evidence in the room - never gets to confirm anything.
    """
    brief = briefing.Brief(subject_kind=args.subject)
    if getattr(args, "brief", None):
        brief = briefing.load(args.brief)
        brief.subject_kind = args.subject
    for pair in getattr(args, "know", []) or []:
        kind, value, certain = briefing.parse_pair(pair)
        brief.add(kind, value, certain=certain)
    if args.target:
        kind = _KIND_FOR_TYPE.get(
            TargetType(args.type) if args.type else detect_type(args.target))
        if kind is not None:
            brief.add(kind, args.target)
    return brief.expand() if brief else brief


#: The claim a positional target amounts to.
_KIND_FOR_TYPE = {
    TargetType.DOMAIN: briefing.ClaimKind.DOMAIN,
    TargetType.EMAIL: briefing.ClaimKind.EMAIL,
    TargetType.USERNAME: briefing.ClaimKind.USERNAME,
    TargetType.PERSON: briefing.ClaimKind.NAME,
    TargetType.PHONE: briefing.ClaimKind.PHONE,
    TargetType.URL: briefing.ClaimKind.URL,
    TargetType.IP: briefing.ClaimKind.IP,
}


def _budget(args: argparse.Namespace):
    """Turn --budget/--depth/--max-entities into an expansion budget."""
    from .core.engine import Budget

    budget = {"quick": Budget.quick, "deep": Budget.deep}.get(args.budget, Budget)()
    if args.depth is not None:
        budget.max_depth = args.depth
    if args.max_entities is not None:
        budget.max_entities = args.max_entities
    return budget


def _open_store(args: argparse.Namespace):
    """The case store for this scan, or ``None`` if we are not recording.

    Opened *before* the engine, not after, so the evidence store is in place for
    the first request. A store attached at the end records the findings but none
    of the bytes they came from, which makes ``nova replay`` silently useless -
    it reports 0% coverage on a case that looks complete.
    """
    if args.no_save:
        return None
    try:
        from .core.store import CaseStore

        return CaseStore(getattr(args, "case_dir", None))
    except Exception as exc:  # noqa: BLE001 - filing must never cost the findings
        log.warning("case store unavailable, this scan will not be saved: %s: %s",
                    type(exc).__name__, exc)
        return None


def _save_case(store, args: argparse.Namespace, inv) -> str:
    """Record the scan. Never fails it.

    A scan that completed and could not be filed is still a scan the user wants
    to read, so every failure here is a warning and nothing more.
    """
    if store is None:
        return ""
    try:
        from . import commands

        cid = store.save(inv, inv.graph, label=args.label, requests=inv.requests)
        return commands.summarise_for_terminal(store, cid)
    except Exception as exc:  # noqa: BLE001
        log.warning("could not save this scan: %s: %s", type(exc).__name__, exc)
        return ""


def cmd_scan(args: argparse.Namespace) -> int:
    manager, cfg = load_config(args)
    try:
        brief = _build_brief(args)
    except briefing.BriefError as exc:
        print(exc, file=sys.stderr)
        return EXIT_USAGE

    if not args.target:
        # No positional target, so the brief has to supply one. Its strongest
        # identifier leads, which is also the one worth spending first.
        seeds = brief.seeds if brief else []
        if not seeds:
            print("give a target, or describe the subject with --know "
                  "(for example: nova scan -K name='Ada Lovelace' -K born=1815)",
                  file=sys.stderr)
            return EXIT_USAGE
        args.target = seeds[0].value
        args.type = args.type or briefing.SEEDABLE[seeds[0].kind].value

    ttype = TargetType(args.type) if args.type else detect_type(args.target)
    if ttype == TargetType.UNKNOWN:
        print(f"could not work out what '{args.target}' is; pass --type", file=sys.stderr)
        return EXIT_USAGE

    if not args.quiet and not args.no_art:
        art.intro(sys.stderr)
        sys.stderr.write(art.section(ttype.value))

    for problem in manager.problems:
        print(f"config: {problem}", file=sys.stderr)

    progress = Progress(not args.quiet and not args.verbose)
    started = time.time()
    store = _open_store(args)
    evidence = store.evidence if store is not None else None
    with Engine(cfg, progress=progress, evidence=evidence) as engine:
        only = args.only.split(",") if args.only else None
        exclude = args.exclude.split(",") if args.exclude else None
        try:
            _, runnable, skipped = engine.plan(args.target, only, exclude, ttype)
        except ValueError as exc:  # unknown module name in --only
            if store is not None:
                store.close()
            print(exc, file=sys.stderr)
            return EXIT_USAGE

        if not runnable:
            progress.clear()
            if store is not None:
                store.close()
            reasons = {reason for _, reason in skipped}
            if len(reasons) == 1 and len(skipped) > 1:
                # One cause stopped everything - almost always a --type that
                # the value cannot satisfy. Saying it once and naming the fix
                # beats ten identical lines the reader has to diff by eye.
                reason = reasons.pop()
                print(f"cannot scan {args.target!r} as a {ttype.value}: {reason}",
                      file=sys.stderr)
                suggested = detect_type(args.target)
                if suggested not in (ttype, TargetType.UNKNOWN):
                    print(f"  try: nova scan {args.target!r} "
                          f"--type {suggested.value}", file=sys.stderr)
                else:
                    print(f"  ({len(skipped)} module(s) skipped)", file=sys.stderr)
            else:
                print(f"no modules accept a {ttype.value} target with these filters",
                      file=sys.stderr)
                for name, reason in skipped:
                    print(f"  skipped {name}: {reason}", file=sys.stderr)
            return EXIT_NOTHING_RAN
        if not args.quiet:
            print(f"target: {args.target}  type: {ttype.value}  "
                  f"modules: {', '.join(m.name for m in runnable)}", file=sys.stderr)
            for name, reason in skipped:
                print(f"  skipping {name} ({reason})", file=sys.stderr)
            if len(brief) > 1:
                print(f"brief: {len(brief)} fact(s) - "
                      + ", ".join(f"{c.kind.value}={c.raw}" for c in brief.claims),
                      file=sys.stderr)
            print(file=sys.stderr)

        # A brief with more than the target in it means cross-checking, which
        # only the expanding walk can do: it is the one path that puts every
        # seed into a single graph where the evidence can converge.
        resolving = len(brief) > 1
        if args.expand or resolving:
            inv = engine.investigate(args.target, only, exclude, ttype,
                                     budget=_budget(args),
                                     brief=brief if resolving else None)
        else:
            inv = engine.scan(args.target, only, exclude, ttype)
        pivot_scans = []
        if args.pivot and not args.expand:
            # --expand supersedes --pivot; running both would scan the same
            # entities twice and print them under two different headings.
            pivot_scans = engine.follow_pivots(inv, limit=args.pivot_limit)
    progress.clear()

    case_id = _save_case(store, args, inv)
    if store is not None:
        store.close()

    rendered = inv
    if args.redact:
        from .core.graphview import Redactor, redact_investigation

        redactor = Redactor(True, args.redact_salt)
        # Redact a copy. The store already holds the real values, and mutating
        # in place would redact whatever ran afterwards - including the save.
        rendered = redact_investigation(inv, redactor)
        if not args.quiet:
            print(f"redacted {redactor.count} personal value(s) from the output",
                  file=sys.stderr)

    inv = rendered
    if args.format == "console":
        out = reporting.render_console(
            inv, verbose=args.verbose > 0, min_severity=Severity(args.min_severity)
        )
        for extra in pivot_scans:
            out += "\n" + reporting.render_console(extra, min_severity=Severity(args.min_severity))
    elif args.format == "json":
        out = reporting.render_json(inv, pivot_scans)
    else:
        out = reporting.RENDERERS[args.format](inv)

    if args.expand and inv.expansion is not None and not args.quiet:
        exp = inv.expansion
        print(f"\nexpanded {len(exp.expanded)} entit(ies) over {exp.rounds} "
              f"round(s); stopped by {exp.stopped_by}", file=sys.stderr)
        for eid, score in exp.unexplored[:5]:
            print(f"  not reached: {eid} (score {score:.3f})", file=sys.stderr)
    if case_id and not args.quiet:
        print(case_id, file=sys.stderr)

    if args.output:
        destination = _resolve_output(args.output, cfg)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(out, "utf-8")
        print(f"wrote {destination}  ({len(inv.findings)} findings, "
              f"{time.time() - started:.1f}s)", file=sys.stderr)
    else:
        sys.stdout.write(out if out.endswith("\n") else out + "\n")

    # An incomplete scan with findings is still a successful run; the report
    # says which instruments fell short, so the exit code stays about findings.
    return EXIT_OK if inv.findings else EXIT_NO_FINDINGS


#: Subcommands that read the case store and nothing else.
_CASE_COMMANDS = frozenset({"history", "show", "diff", "link", "where", "replay",
                            "evidence", "phone"})


def _run_case_command(args: argparse.Namespace) -> int:
    """Open the case store once and hand it to the right command.

    The store is opened here rather than inside each command so there is exactly
    one place that decides where cases live, and exactly one that closes the
    connection.
    """
    from . import commands
    from .core.store import CaseStore

    _, cfg = load_config(args)
    try:
        store = CaseStore(getattr(args, "case_dir", None))
    except RuntimeError as exc:  # a newer schema; refusing beats corrupting
        print(exc, file=sys.stderr)
        return EXIT_USAGE
    except OSError as exc:
        # An unwritable --case-dir is a typo, not a crash. A traceback here
        # buries the one thing the user needs to see: which path failed.
        print(f"cannot open the case store: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        if args.command == "history":
            return commands.cmd_history(args, store)
        if args.command == "show":
            return commands.cmd_show(args, store)
        if args.command == "diff":
            return commands.cmd_diff(args, store)
        if args.command == "link":
            return commands.cmd_link(args, store)
        if args.command == "where":
            return commands.cmd_where(args, store)
        if args.command == "replay":
            return commands.cmd_replay(args, store, cfg)
        if args.command == "evidence":
            return commands.cmd_evidence(args, store)
        if args.command == "phone":
            # Handed the store so the card can say whether this number has
            # turned up in an earlier case.
            return commands.cmd_phone(args, cfg, store)
    finally:
        store.close()
    return EXIT_USAGE


def _force_utf8() -> None:
    """Windows consoles default to cp1252, which cannot encode box drawing.

    Without this the tool dies with a UnicodeEncodeError the first time it
    prints a table - on Windows, which is where a lot of people will run it.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError, OSError):
            pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8()
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "investigate":
        from .investigation_cli import cmd_investigate

        manager, cfg = load_config(args)
        for problem in manager.problems:
            print(f"config: {problem}", file=sys.stderr)
        if not args.quiet and not args.no_art:
            art.intro(sys.stderr)
        return cmd_investigate(args, manager, cfg, _build_brief, _budget,
                               _open_store, _save_case, _resolve_output)
    if args.command == "browser":
        from .investigation_cli import cmd_browser

        _, cfg = load_config(args)
        return cmd_browser(args, cfg)
    if args.command == "modules":
        return cmd_modules(args)
    if args.command == "config":
        return cmd_config(args)
    if args.command in _CASE_COMMANDS:
        return _run_case_command(args)
    if args.command == "doctor":
        from . import commands

        _, cfg = load_config(args)
        return commands.cmd_doctor(args, cfg)
    if args.command == "legal":
        print(LEGAL)
        return EXIT_OK
    if args.command == "art":
        art.animate(sys.stdout, seconds=5.0)
        sys.stdout.write(art.gallery())
        return EXIT_OK
    if args.command == "gui":
        from .gui import main as gui_main

        return gui_main()
    parser.print_help()
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
