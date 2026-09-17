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
  nova scan example.com
  nova scan alice@example.com --format html --output report.html
  nova scan someuser --only username
  nova scan 8.8.8.8 --pivot
  nova scan example.com --passive --quiet --format json
  nova scan example.com -vv --log-file scan.log
  nova modules
  nova config show
  nova art
""",
    )
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="run a scan against one target")
    scan.add_argument("target", help="domain, email, username, IP, phone number or URL")
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
    scan.add_argument("-q", "--quiet", action="store_true", help="no banner, no progress")
    scan.add_argument("--no-art", action="store_true", help="keep the progress line, drop the ASCII art")
    _common(scan)

    mods = sub.add_parser("modules", help="list available modules")
    mods.add_argument("-t", "--type", choices=[t.value for t in TargetType],
                      help="only modules that accept this target type")
    _common(mods)

    cfg = sub.add_parser("config", help="show, create or locate the configuration file")
    cfg.add_argument("action", nargs="?", default="show", choices=["show", "init", "path"],
                     help="show (default, API keys masked), init, or path")
    _common(cfg)

    sub.add_parser("legal", help="print the usage and legal notice")
    sub.add_parser("art", help="show every banner NOVA can draw")
    sub.add_parser("gui", help="open the desktop app")
    return p


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


def cmd_scan(args: argparse.Namespace) -> int:
    manager, cfg = load_config(args)
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
    with Engine(cfg, progress=progress) as engine:
        only = args.only.split(",") if args.only else None
        exclude = args.exclude.split(",") if args.exclude else None
        try:
            _, runnable, skipped = engine.plan(args.target, only, exclude, ttype)
        except ValueError as exc:  # unknown module name in --only
            print(exc, file=sys.stderr)
            return EXIT_USAGE

        if not runnable:
            progress.clear()
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
            print(file=sys.stderr)

        inv = engine.scan(args.target, only, exclude, ttype)
        pivot_scans = []
        if args.pivot:
            pivot_scans = engine.follow_pivots(inv, limit=args.pivot_limit)
    progress.clear()

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
    if args.command == "modules":
        return cmd_modules(args)
    if args.command == "config":
        return cmd_config(args)
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
