"""Command line interface."""

from __future__ import annotations

import argparse
import sys
import threading
import time
from pathlib import Path

from .core import art
from .core import report as reporting
from .core.config import DEFAULT_CACHE, KEY_ENV, Config, load_env_file
from .core.engine import Engine
from .core.models import Severity, TargetType
from .core.registry import all_modules, detect_type

LEGAL = """\
NOVA queries public sources only. You are responsible for using it
lawfully: have authorisation for the target, respect each source's terms, and
remember that "publicly available" is not the same as "fair to aggregate".
Scanning people or infrastructure you have no relationship with can be illegal
where you are.
"""


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
  nova modules
  nova art
""",
    )
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="run a scan against one target")
    scan.add_argument("target", help="domain, email, username, IP, phone number or URL")
    scan.add_argument("-t", "--type", choices=[t.value for t in TargetType if t != TargetType.UNKNOWN],
                      help="force the target type instead of auto-detecting")
    scan.add_argument("-o", "--output", type=Path, help="write the report to a file")
    scan.add_argument("-f", "--format", choices=sorted(reporting.RENDERERS),
                      default="console", help="output format (default: console)")
    scan.add_argument("--only", help="comma-separated module names to run exclusively")
    scan.add_argument("--exclude", help="comma-separated module names to skip")
    scan.add_argument("--passive", action="store_true",
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
    scan.add_argument("--max-sites", type=int, default=0,
                      help="cap the number of sites / subdomains probed (0 = no cap)")
    scan.add_argument("--min-severity", choices=[s.value for s in Severity], default="info",
                      help="hide findings below this interest level")
    scan.add_argument("-q", "--quiet", action="store_true", help="no banner, no progress")
    scan.add_argument("--no-art", action="store_true", help="keep the progress line, drop the ASCII art")
    scan.add_argument("-v", "--verbose", action="store_true", help="show empty modules and warnings")
    _common(scan)

    mods = sub.add_parser("modules", help="list available modules")
    mods.add_argument("-t", "--type", choices=[t.value for t in TargetType],
                      help="only modules that accept this target type")
    _common(mods)

    sub.add_parser("legal", help="print the usage and legal notice")
    sub.add_parser("art", help="show every banner NOVA can draw")
    sub.add_parser("gui", help="open the desktop app")
    return p


def _common(sp: argparse.ArgumentParser) -> None:
    g = sp.add_argument_group("network")
    g.add_argument("--timeout", type=float, default=12.0, help="per-request timeout (s)")
    g.add_argument("--concurrency", type=int, default=24, help="parallel requests")
    g.add_argument("--delay", type=float, default=0.35, dest="per_host_delay",
                   help="minimum seconds between requests to the same host")
    g.add_argument("--retries", type=int, default=2, help="retries on 429/503")
    g.add_argument("--proxy", help="http(s) proxy, e.g. socks-fronted http://127.0.0.1:8080")
    g.add_argument("--user-agent", help="override the User-Agent header")
    g.add_argument("--insecure", action="store_true", dest="insecure",
                   help="do not verify TLS certificates")
    g.add_argument("--no-cache", action="store_true", help="bypass the on-disk response cache")
    g.add_argument("--cache-ttl", type=float, default=3600.0, help="cache lifetime (s)")
    g.add_argument("--env-file", type=Path, help="load API keys from this KEY=value file")


def make_config(args: argparse.Namespace) -> Config:
    if getattr(args, "env_file", None):
        n = load_env_file(args.env_file)
        print(f"loaded {n} key(s) from {args.env_file}", file=sys.stderr)
    cfg = Config.from_env(
        timeout=args.timeout,
        concurrency=args.concurrency,
        per_host_delay=args.per_host_delay,
        retries=args.retries,
        proxy=args.proxy,
        user_agent=args.user_agent,
        verify_tls=not args.insecure,
        cache_ttl=args.cache_ttl,
        cache_dir=None if args.no_cache else DEFAULT_CACHE / "http",
        passive_only=getattr(args, "passive", False),
        max_sites=getattr(args, "max_sites", 0),
    )
    # Module-local switches ride on the config rather than widening every
    # module signature for options only one module cares about.
    cfg._verify_hits = getattr(args, "verify", False)          # type: ignore[attr-defined]
    cfg._refresh_sites = getattr(args, "refresh_sites", False)  # type: ignore[attr-defined]
    cfg._include_nsfw = getattr(args, "include_nsfw", False)    # type: ignore[attr-defined]
    return cfg


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
    cfg = make_config(args)
    wanted = TargetType(args.type) if args.type else None
    rows = []
    for cls in all_modules():
        if wanted and wanted not in cls.accepts:
            continue
        need = cls.requires_key
        status = "ready"
        if need and not cfg.has(need):
            status = f"needs ${KEY_ENV.get(need, need)}"
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
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    cfg = make_config(args)
    ttype = TargetType(args.type) if args.type else detect_type(args.target)
    if ttype == TargetType.UNKNOWN:
        print(f"could not work out what '{args.target}' is; pass --type", file=sys.stderr)
        return 2

    if not args.quiet and not args.no_art:
        art.intro(sys.stderr)
        sys.stderr.write(art.section(ttype.value))

    progress = Progress(not args.quiet)
    started = time.time()
    with Engine(cfg, progress=progress) as engine:
        _, runnable, skipped = engine.plan(
            args.target,
            only=args.only.split(",") if args.only else None,
            exclude=args.exclude.split(",") if args.exclude else None,
            target_type=ttype,
        )
        if not runnable:
            progress.clear()
            print(f"no modules accept a {ttype.value} target with these filters", file=sys.stderr)
            for name, reason in skipped:
                print(f"  skipped {name}: {reason}", file=sys.stderr)
            return 1
        if not args.quiet:
            print(f"target: {args.target}  type: {ttype.value}  "
                  f"modules: {', '.join(m.name for m in runnable)}", file=sys.stderr)
            for name, reason in skipped:
                print(f"  skipping {name} ({reason})", file=sys.stderr)
            print(file=sys.stderr)

        inv = engine.scan(
            args.target,
            only=args.only.split(",") if args.only else None,
            exclude=args.exclude.split(",") if args.exclude else None,
            target_type=ttype,
        )
        pivot_scans = []
        if args.pivot:
            pivot_scans = engine.follow_pivots(inv, limit=args.pivot_limit)
    progress.clear()

    if args.format == "console":
        out = reporting.render_console(
            inv, verbose=args.verbose, min_severity=Severity(args.min_severity)
        )
        for extra in pivot_scans:
            out += "\n" + reporting.render_console(extra, min_severity=Severity(args.min_severity))
    elif args.format == "json":
        out = reporting.render_json(inv, pivot_scans)
    else:
        out = reporting.RENDERERS[args.format](inv)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(out, "utf-8")
        print(f"wrote {args.output}  ({len(inv.findings)} findings, "
              f"{time.time() - started:.1f}s)", file=sys.stderr)
    else:
        sys.stdout.write(out if out.endswith("\n") else out + "\n")

    return 0 if inv.findings else 1


def _force_utf8() -> None:
    """Windows consoles default to cp1252, which cannot encode box drawing.

    Without this the tool dies with a UnicodeEncodeError the first time it
    prints a table - on Windows, which is where a lot of people will run it.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8()
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "modules":
        return cmd_modules(args)
    if args.command == "legal":
        print(LEGAL)
        return 0
    if args.command == "art":
        art.animate(sys.stdout, seconds=5.0)
        sys.stdout.write(art.gallery())
        return 0
    if args.command == "gui":
        from .gui import main as gui_main

        return gui_main()
    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
