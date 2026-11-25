"""The commands that work on saved cases, plus the pre-flight check.

``cli.py`` owns argument parsing and the scan pipeline; this owns everything
that reads the case store or probes the outside world without scanning anything:
``history``, ``show``, ``diff``, ``link``, ``replay``, ``evidence`` and
``doctor``.

They share one idea with the rest of NOVA: **say what you could not do**. A
history with no cases, a diff between runs where a module went dark, a doctor
run from behind a filtering proxy - each of those has an answer that is not
"nothing found", and each one prints it.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from typing import Any

from .core import report as reporting
from .core.config import KEY_ENV, Config
from .core.entities import Entity, EntityType
from .core.http import AccessStatus, Fetcher
from .core.logging_config import get_logger
from .core.store import CaseStore

log = get_logger("commands")

EXIT_OK = 0
EXIT_NO_FINDINGS = 1
EXIT_USAGE = 2

#: Timeouts that match what the modules actually allow. crt.sh regularly takes
#: 20-40 seconds under load and the subdomain module gives it 45; a 10-second
#: probe reports it down while the scan that follows uses it happily.
SLOW = 45.0

DNS_JSON = {"accept": "application/dns-json"}


@dataclass(frozen=True)
class Probe:
    source: str
    url: str
    provides: str
    key: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    timeout: float = 10.0


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------

#: Every external source NOVA can use, with a request that proves reachability
#: without being a scan of anybody. Answers the question the coverage-gaps
#: section raises after the fact - "why was this empty?" - before the scan.
#: Each probe carries the headers and timeout its module uses. That is not
#: tidiness. The first version sent a bare GET to the DoH resolvers and reported
#: a perfectly healthy Cloudflare as unreachable, because DoH answers 400
#: without an accept: application/dns-json header. A checker that calls a
#: working source broken is worse than no checker - people learn to ignore it.
PROBES: list[Probe] = [
    Probe("dns.google", "https://dns.google/resolve?name=example.com&type=A",
          "DNS over HTTPS (primary resolver)", headers=DNS_JSON),
    Probe("cloudflare-dns",
          "https://cloudflare-dns.com/dns-query?name=example.com&type=A",
          "DNS over HTTPS (fallback resolver)", headers=DNS_JSON),
    Probe("rdap.org", "https://rdap.org/domain/example.com",
          "domain registration records", timeout=20.0),
    Probe("crt.sh", "https://crt.sh/?q=example.com&output=json",
          "certificate transparency (subdomains)", timeout=SLOW),
    Probe("certspotter",
          "https://api.certspotter.com/v1/issuances?domain=example.com",
          "certificate transparency (second opinion)", timeout=30.0),
    Probe("hackertarget", "https://api.hackertarget.com/hostsearch/?q=example.com",
          "host search"),
    Probe("rapiddns", "https://rapiddns.io/subdomain/example.com",
          "subdomain records", timeout=30.0),
    Probe("ip-api.com", "http://ip-api.com/json/8.8.8.8",
          "IP geolocation and ASN"),
    Probe("internetdb.shodan", "https://internetdb.shodan.io/8.8.8.8",
          "open ports and CVEs (keyless)"),
    Probe("web.archive.org", "https://archive.org/wayback/available?url=example.com",
          "archive history", timeout=20.0),
    Probe("haveibeenpwned", "https://haveibeenpwned.com/api/v3/breaches",
          "breach catalogue (keyless endpoint)", timeout=20.0),
    Probe("gravatar", "https://www.gravatar.com/avatar/0?d=404",
          "avatar and profile by email hash"),
    Probe("keybase", "https://keybase.io/_/api/1.0/user/lookup.json?usernames=chris",
          "signed identity proofs"),
    Probe("npm", "https://registry.npmjs.org/-/v1/search?text=maintainer:npm&size=1",
          "package authorship and publisher email"),
    Probe("crates.io", "https://crates.io/api/v1/users/rust-lang-owner",
          "crate authorship"),
    Probe("api.github.com", "https://api.github.com/rate_limit",
          "profiles, repos, keys, commit emails", key="github"),
    Probe("virustotal", "https://www.virustotal.com/api/v3/domains/example.com",
          "passive DNS and reputation", key="virustotal"),
    Probe("securitytrails", "https://api.securitytrails.com/v1/ping",
          "DNS history (paid plan)", key="securitytrails"),
    Probe("abuseipdb", "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8",
          "abuse reports", key="abuseipdb"),
]


def cmd_doctor(args: argparse.Namespace, cfg: Config) -> int:
    """Ask every source whether it will talk to this machine, and say so.

    The honest version of a connectivity check. It distinguishes "reachable",
    "refused us", "rate limited" and "needs a key you do not have", because
    those produce identical empty results in a report and mean four different
    things. Run it once from a new network and the coverage gaps stop being a
    surprise at the end of a fifteen-minute scan.
    """
    if getattr(args, "leak_check", False):
        return _leak_report(args, cfg)

    probes = PROBES
    if getattr(args, "keyless", False):
        probes = [p for p in probes if p.key is None]

    print(f"NOVA doctor - probing {len(probes)} source(s) from this machine\n")
    fetcher = Fetcher(timeout=args.timeout or 10.0, concurrency=args.concurrency or 8,
                      retries=0, cache_dir=None, proxy=args.proxy,
                      verify_tls=not getattr(args, "insecure", False))
    try:
        results = fetcher.map(
            lambda p: (p, fetcher.get(p.url, headers=dict(p.headers),
                                      timeout=args.timeout or p.timeout)),
            probes)
    finally:
        fetcher.close()

    width = max(len(p.source) for p in probes)
    ok = gated = broken = 0
    rows = []
    for probe, resp in results:
        name, what, key = probe.source, probe.provides, probe.key
        have_key = bool(key and cfg.has(key))
        verdict, note = _verdict(resp, key, have_key)
        if verdict == "ok":
            ok += 1
        elif verdict == "key":
            gated += 1
        else:
            broken += 1
        rows.append((name, verdict, note, what))
        print(f"  {_mark(verdict)}  {name.ljust(width)}  {note.ljust(34)}  {what}")

    print(f"\n{ok} reachable, {gated} waiting on a key, {broken} unavailable")
    if broken:
        print("\nAn unavailable source is not an empty result. A scan will report these\n"
              "as coverage gaps rather than pretending it looked.", file=sys.stderr)
    if gated:
        missing = sorted({KEY_ENV.get(p.key, p.key or "") for p in probes
                          if p.key and not cfg.has(p.key)})
        print(f"Set these to widen coverage: {', '.join(missing)}", file=sys.stderr)
    if getattr(args, "format", None) == "json":
        print(json.dumps([{"source": n, "verdict": v, "note": t, "provides": w}
                          for n, v, t, w in rows], indent=2))
    return EXIT_OK if ok else EXIT_NO_FINDINGS


def _leak_report(args: argparse.Namespace, cfg: Config) -> int:
    """Does the proxy actually change the address we present?

    A scan configured to go through a proxy and silently falling back to the
    direct route looks identical from the inside, and the difference is the
    analyst's own address in somebody's logs. Refusing to answer is the only
    honest outcome when there is nothing to compare.
    """
    from .core.opsec import leak_check

    proxy = args.proxy or cfg.proxy
    if not proxy:
        print("no proxy configured, so there is nothing to compare.",
              file=sys.stderr)
        print("Pass --proxy to check that it is actually being used.",
              file=sys.stderr)
        return EXIT_USAGE

    direct = Fetcher(timeout=15.0, concurrency=1, retries=0, cache_dir=None)
    proxied = Fetcher(timeout=15.0, concurrency=1, retries=0, cache_dir=None,
                      proxy=proxy)
    try:
        report = leak_check(direct, proxied)
    finally:
        direct.close()
        proxied.close()

    if report["error"]:
        print(f"could not complete the check: {report['error']}", file=sys.stderr)
        print("Treat that as a failure, not a pass.", file=sys.stderr)
        return EXIT_NO_FINDINGS
    print(f"  direct   {report['direct']}")
    print(f"  proxied  {report['proxied']}")
    if report["leaking"]:
        print("", file=sys.stderr)
        print("  LEAKING: both routes present the same address. The proxy is not",
              file=sys.stderr)
        print("  carrying your traffic, and a scan through it exposes you exactly",
              file=sys.stderr)
        print("  as much as one without it.", file=sys.stderr)
        return EXIT_NO_FINDINGS
    print("")
    print("  the proxy is carrying the traffic.")
    return EXIT_OK


def _verdict(resp: Any, key: str | None, have_key: bool) -> tuple[str, str]:
    """Turn one probe response into a verdict a person can act on."""
    access = resp.access
    # A keyed source answering 401/403 without a key is working correctly; that
    # is not the same failure as a source refusing a request that had one.
    if key and not have_key and access in (AccessStatus.ACCESS_DENIED,):
        return "key", f"needs ${KEY_ENV.get(key, key.upper())}"
    if key and not have_key and resp.status in (401, 403):
        return "key", f"needs ${KEY_ENV.get(key, key.upper())}"
    if access is AccessStatus.OK:
        return "ok", f"ok ({resp.elapsed:.2f}s)"
    if access is AccessStatus.NOT_FOUND:
        return "ok", f"reachable, 404 ({resp.elapsed:.2f}s)"
    if access is AccessStatus.RATE_LIMITED:
        return "limited", "rate limited right now"
    if access in (AccessStatus.ACCESS_DENIED, AccessStatus.BLOCKED):
        return "blocked", f"refused us ({resp.status})"
    return "down", (resp.error or f"unreachable ({resp.status})")[:34]


def _mark(verdict: str) -> str:
    return {"ok": "+", "key": "-", "limited": "~"}.get(verdict, "x")


# ---------------------------------------------------------------------------
# phone
# ---------------------------------------------------------------------------


def cmd_phone(args: argparse.Namespace, cfg: Config, store: Any = None) -> int:
    """One number in, one card out.

    A thin command on purpose: it runs the ordinary phone module, then asks the
    case store whether this number has been seen before, and renders the two
    together. The lookup against the operator's own history is the part a
    caller-ID app cannot do and the part that is actually theirs.
    """
    from .core.engine import Engine
    from .core.models import TargetType
    from .core.phonecard import build, render_json, render_text

    with Engine(cfg) as engine:
        inv = engine.scan(args.number, target_type=TargetType.PHONE)
    card = build(inv, store)
    if store is not None:
        # The lookup itself is not saved as a case - a card is not an
        # investigation, and filing one would make every future lookup report
        # "seen before: the time you looked it up". It does go in the audit
        # chain, because what this tool was pointed at is exactly what that log
        # is for.
        try:
            store.audit.append("phone-lookup", number=card.formats.get(
                "E.164", args.number), verdict=card.verdict, risk=card.risk)
        except Exception as exc:  # noqa: BLE001 - never lose the card over a log
            log.warning("could not record the lookup: %s", exc)

    if args.format == "json":
        print(render_json(card))
    else:
        sys.stdout.write(render_text(card))

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            render_json(card) if args.format == "json" else render_text(card), "utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    # A number that does not exist is a real answer, so it is a success. Only a
    # parse that produced nothing at all counts as finding nothing.
    return EXIT_OK if card.verdict else EXIT_NO_FINDINGS


# ---------------------------------------------------------------------------
# history / show
# ---------------------------------------------------------------------------


def cmd_history(args: argparse.Namespace, store: CaseStore) -> int:
    cases = store.cases(target=args.target, limit=args.limit)
    if not cases:
        where = f" for {args.target}" if args.target else ""
        print(f"no saved cases{where}. Scans are saved unless --no-save is passed.",
              file=sys.stderr)
        print(f"store: {store.root}", file=sys.stderr)
        return EXIT_NO_FINDINGS
    if args.format == "json":
        print(json.dumps([c.to_dict() for c in cases], indent=2))
        return EXIT_OK

    width = max(len(c.target) for c in cases)
    print(f"{'CASE'.ljust(22)}  {'WHEN'.ljust(17)}  {'TARGET'.ljust(width)}  FINDINGS")
    print("-" * (52 + width))
    for c in cases:
        s = c.summary or {}
        bits = f"{s.get('findings', 0)} findings"
        if s.get("entities"):
            bits += f", {s['entities']} entities"
        if s.get("incomplete"):
            bits += f", {s['incomplete']} incomplete"
        print(f"{c.id.ljust(22)}  {c.when.ljust(17)}  {c.target.ljust(width)}  {bits}")
    stats = store.stats()
    chain = "intact" if stats["audit_intact"] else "BROKEN - the log has been edited"
    print(f"\n{stats['cases']} case(s), {stats['evidence_files']} evidence file(s) "
          f"({stats['evidence_bytes'] / 1e6:.1f} MB), audit chain {chain}",
          file=sys.stderr)
    return EXIT_OK


def cmd_show(args: argparse.Namespace, store: CaseStore) -> int:
    record = store.case(args.case)
    if record is None:
        print(f"no such case: {args.case}", file=sys.stderr)
        return EXIT_USAGE
    if args.format == "json":
        print(json.dumps({
            "case": record.to_dict(),
            "findings": [dict(r) for r in store.findings(record.id)],
            "graph": store.graph(record.id).to_dict(),
            "statuses": {m: {"status": s, "reason": r}
                         for m, (s, r) in store.statuses(record.id).items()},
        }, indent=2, default=str))
        return EXIT_OK

    graph = store.graph(record.id)
    print(f"case {record.id}   {record.when}   {record.duration:.1f}s")
    print(f"target: {record.target} ({record.target_type})\n")

    findings = store.findings(record.id)
    by_module: dict[str, list[Any]] = {}
    for row in findings:
        by_module.setdefault(row["module"], []).append(row)
    for module, rows in sorted(by_module.items()):
        status, reason = store.statuses(record.id).get(module, ("", ""))
        head = f"{module}  [{status}]" + (f" - {reason}" if reason else "")
        print(head)
        for row in rows:
            ev = f"  evidence:{row['evidence'][:12]}" if row["evidence"] else ""
            print(f"    {row['label']}: {row['value']}{ev}")
        print()

    if len(graph):
        print(f"entities ({len(graph)}), most relevant first:")
        for node in sorted(graph, key=lambda n: -n.score)[:args.limit]:
            path = " -> ".join(graph.path(node.entity.eid)) or node.entity.eid
            print(f"  {node.score:5.3f}  d{node.depth}  {node.entity.eid}")
            if node.depth:
                print(f"           via {path}")
    for module, (status, reason) in sorted(store.statuses(record.id).items()):
        if status not in ("success", "empty"):
            print(f"\ncoverage gap: {module} - {status}" + (f" ({reason})" if reason else ""))
    return EXIT_OK


# ---------------------------------------------------------------------------
# diff / link
# ---------------------------------------------------------------------------


def cmd_diff(args: argparse.Namespace, store: CaseStore) -> int:
    """Compare two cases, or the last two runs against one target."""
    if args.new is None:
        cases = store.cases(target=args.old, limit=2)
        if len(cases) < 2:
            print(f"need two saved cases for {args.old}; found {len(cases)}",
                  file=sys.stderr)
            return EXIT_USAGE
        new_rec, old_rec = cases[0], cases[1]
    else:
        old_rec, new_rec = store.case(args.old), store.case(args.new)
        if old_rec is None or new_rec is None:
            print("unknown case id", file=sys.stderr)
            return EXIT_USAGE

    changes = store.diff(old_rec.id, new_rec.id)
    if args.format == "json":
        print(json.dumps({"old": old_rec.to_dict(), "new": new_rec.to_dict(),
                          "changes": [c.to_dict() for c in changes]}, indent=2))
        return EXIT_OK if changes else EXIT_NO_FINDINGS

    print(f"{old_rec.id}  ({old_rec.when})")
    print(f"{new_rec.id}  ({new_rec.when})   {old_rec.target}\n")
    if not changes:
        print("no change.")
        return EXIT_NO_FINDINGS

    # Coverage changes go first. "This module stopped working" reframes every
    # removal under it, and a reader who meets the removals first has already
    # drawn the wrong conclusion by the time they reach the explanation.
    order = {"status": 0, "finding": 1, "entity": 2, "edge": 3}
    for change in sorted(changes, key=lambda c: (order.get(c.scope, 9), c.kind, c.key)):
        mark = {"added": "+", "removed": "-", "changed": "~"}[change.kind]
        if change.scope == "status":
            print(f"  {mark} coverage  {change.key}: {change.before} -> {change.after}"
                  + (f" ({change.detail})" if change.detail else ""))
        elif change.kind == "changed":
            print(f"  {mark} {change.key}")
            print(f"      was: {change.before}")
            print(f"      now: {change.after}")
        else:
            value = change.after if change.kind == "added" else change.before
            suffix = f": {value}" if value else ""
            print(f"  {mark} {change.key}{suffix}")
    counts: dict[str, int] = {}
    for c in changes:
        counts[c.kind] = counts.get(c.kind, 0) + 1
    print("\n" + ", ".join(f"{n} {k}" for k, n in sorted(counts.items())))
    return EXIT_OK


def cmd_link(args: argparse.Namespace, store: CaseStore) -> int:
    """What two investigations have in common - the cross-case correlation."""
    a, b = store.case(args.case_a), store.case(args.case_b)
    if a is None or b is None:
        print("unknown case id", file=sys.stderr)
        return EXIT_USAGE
    shared = store.link(a.id, b.id)
    real = [row for row in shared if not row["shared_infrastructure"]]
    infra = [row for row in shared if row["shared_infrastructure"]]

    if args.format == "json":
        print(json.dumps({"a": a.to_dict(), "b": b.to_dict(), "shared": shared}, indent=2))
        return EXIT_OK if real else EXIT_NO_FINDINGS

    print(f"{a.target} ({a.id})  <->  {b.target} ({b.id})\n")
    if not shared:
        print("nothing in common.")
        return EXIT_NO_FINDINGS
    if real:
        print("shared entities:")
        for row in real:
            print(f"  {row['score']:5.3f}  {row['type']:<9} {row['value']}")
    if infra:
        # Reported, never counted as a link: two unrelated sites both sitting
        # behind one CDN is not a connection between them, and presenting it as
        # one is how a correlation tool manufactures a conspiracy.
        print("\nshared infrastructure (not evidence of a link):")
        for row in infra:
            print(f"         {row['type']:<9} {row['value']}  "
                  f"({row['degree']} neighbours)")
    return EXIT_OK if real else EXIT_NO_FINDINGS


# ---------------------------------------------------------------------------
# replay / evidence
# ---------------------------------------------------------------------------


def cmd_replay(args: argparse.Namespace, store: CaseStore, cfg: Config) -> int:
    from .core.replay import replay

    try:
        inv, report = replay(store, args.case, cfg)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return EXIT_USAGE

    if args.format == "json":
        print(json.dumps({"report": report.to_dict(), "investigation": inv.to_dict()},
                         indent=2, default=str))
        return EXIT_OK if report.clean else EXIT_NO_FINDINGS

    print(f"replaying {report.case_id} ({report.target}) from stored evidence, "
          f"no network\n")
    print(f"  modules re-run      {report.modules}")
    print(f"  responses served    {report.served}  ({report.coverage:.0%} of requests)")
    print(f"  findings then/now   {report.original} / {report.reproduced}")
    if report.missing:
        print(f"\n  {len(report.missing)} request(s) were never recorded, so those "
              f"parsers ran blind:")
        for url in report.missing[:8]:
            print(f"    {url}")
    if report.corrupt:
        print(f"\n  {len(report.corrupt)} evidence blob(s) FAILED verification - "
              f"the stored bytes no longer hash to their own name:")
        for digest in report.corrupt[:8]:
            print(f"    {digest}")
    if report.drift:
        print("\n  finding counts changed since the case was recorded:")
        for module, (then, now) in sorted(report.drift.items()):
            direction = "lost" if now < then else "gained"
            print(f"    {module}: {then} -> {now}  ({direction} {abs(then - now)})")
        print("\n  A module was edited, or its parser broke. The evidence did not"
              "\n  change - it is content-addressed - so the difference is in the code.")
    if report.clean:
        print("\n  reproduced exactly.")
    return EXIT_OK if report.clean else EXIT_NO_FINDINGS


def cmd_evidence(args: argparse.Namespace, store: CaseStore) -> int:
    """Verify the integrity of a case's evidence, or fetch one blob out."""
    if args.digest:
        data = store.evidence.get(args.digest)
        if data is None:
            print(f"no evidence blob {args.digest}", file=sys.stderr)
            return EXIT_USAGE
        if not store.evidence.verify(args.digest):
            print(f"WARNING: {args.digest} does not hash to its own name",
                  file=sys.stderr)
        sys.stdout.write(data.decode("utf-8", "replace"))
        return EXIT_OK

    record = store.case(args.case) if args.case else None
    if args.case and record is None:
        print(f"no such case: {args.case}", file=sys.stderr)
        return EXIT_USAGE

    if record is not None:
        digests = [r["digest"] for r in store.requests(record.id) if r["digest"]]
        scope = f"case {record.id}"
    else:
        digests = [r[0] for r in store.conn.execute(
            "SELECT DISTINCT digest FROM requests WHERE digest IS NOT NULL")]
        scope = "the whole store"

    bad = [d for d in dict.fromkeys(digests) if not store.evidence.verify(d)]
    intact, entries = store.audit.verify()
    stats = store.stats()
    print(f"evidence for {scope}")
    print(f"  blobs referenced   {len(set(digests))}")
    print(f"  store holds        {stats['evidence_files']} file(s), "
          f"{stats['evidence_bytes'] / 1e6:.1f} MB")
    print(f"  failed verification {len(bad)}")
    for digest in bad[:10]:
        print(f"    {digest}")
    if intact:
        print(f"  audit chain        intact ({entries} entries)")
    else:
        print(f"  audit chain        BROKEN at entry {entries} - the log was edited")
    return EXIT_OK if not bad and intact else EXIT_NO_FINDINGS


# ---------------------------------------------------------------------------
# helpers shared with cli
# ---------------------------------------------------------------------------


def cmd_where(args: argparse.Namespace, store: CaseStore) -> int:
    """Which saved cases have ever seen this entity."""
    etype = EntityType(args.type) if args.type else None
    candidates = [etype] if etype else list(EntityType)
    found: list[tuple[EntityType, Any]] = []
    for kind in candidates:
        ent = Entity.make(kind, args.value)
        if ent is None:
            continue
        cases = store.seen_elsewhere(ent)
        if cases:
            found.append((kind, cases))
    if not found:
        print(f"'{args.value}' does not appear in any saved case", file=sys.stderr)
        return EXIT_NO_FINDINGS
    for kind, cases in found:
        print(f"{kind.value}: {args.value}")
        for case in cases:
            print(f"  {case.id}  {case.when}  {case.target}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# reading a saved case back as an investigation
# ---------------------------------------------------------------------------


def investigation_from_case(store: CaseStore, cid: str) -> Any:
    """Rebuild enough of an ``Investigation`` to analyse a saved case offline.

    Not a replay. :mod:`~nova_osint.core.replay` re-runs the parsers against
    stored response bodies to prove they still produce what they produced;
    this only reassembles what was *recorded* - findings, statuses, the graph -
    so the analytical layers can run over an old case without re-parsing
    anything. Cheap, and it opens no socket.

    What it cannot restore is anything the store never kept: the brief, the
    resolution, the expansion bookkeeping. Those layers are simply absent, and
    every detector already treats absent as "not applicable" rather than
    "empty".
    """
    from .core.models import (
        Confidence,
        Finding,
        Investigation,
        ModuleStatus,
        ScanResult,
        Severity,
        TargetType,
    )

    record = store.case(cid)
    if record is None:
        return None
    try:
        ttype = TargetType(record.target_type)
    except ValueError:
        ttype = TargetType.UNKNOWN
    inv = Investigation(target=record.target, target_type=ttype,
                        started_at=record.started_at)
    inv.finished_at = record.started_at + record.duration

    statuses = store.statuses(record.id)
    results: dict[str, Any] = {}
    for row in store.findings(record.id):
        module = row["module"]
        result = results.get(module)
        if result is None:
            status, reason = statuses.get(module, ("success", ""))
            try:
                module_status = ModuleStatus(status)
            except ValueError:
                module_status = ModuleStatus.SUCCESS
            result = ScanResult(module=module, target=record.target,
                                target_type=ttype, status=module_status,
                                status_reason=reason or "",
                                started_at=record.started_at)
            results[module] = result
        try:
            confidence = Confidence(row["confidence"])
        except ValueError:
            confidence = Confidence.POSSIBLE
        try:
            severity = Severity(row["severity"])
        except ValueError:
            severity = Severity.INFO
        result.findings.append(Finding(
            label=row["label"], value=row["value"], source=row["source"],
            confidence=confidence, severity=severity, url=row["url"]))
    # A module that ran and found nothing has a status and no findings, and
    # leaving it out would turn "checked, nothing there" into "never checked".
    for module, (status, reason) in statuses.items():
        if module in results:
            continue
        try:
            module_status = ModuleStatus(status)
        except ValueError:
            module_status = ModuleStatus.SUCCESS
        results[module] = ScanResult(module=module, target=record.target,
                                     target_type=ttype, status=module_status,
                                     status_reason=reason or "",
                                     started_at=record.started_at)
    inv.results = sorted(results.values(), key=lambda r: r.module)
    inv.graph = store.graph(record.id)
    return inv.analyse()


def _case_or_fail(store: CaseStore, cid: str) -> Any:
    inv = investigation_from_case(store, cid)
    if inv is None:
        print(f"no such case: {cid}", file=sys.stderr)
    return inv


def cmd_timeline(args: argparse.Namespace, store: CaseStore) -> int:
    """The chronology of a saved case, as the sources dated it."""
    inv = _case_or_fail(store, args.case)
    if inv is None:
        return EXIT_USAGE
    line = inv.timeline
    if line is None or not line.events:
        print("nothing in this case carries a date a source stood behind.")
        return EXIT_NO_FINDINGS
    if args.format == "json":
        print(json.dumps(line.to_dict(), indent=2, default=str))
        return EXIT_OK
    span = line.span_iso
    print(f"{inv.target}: {len(line.events)} dated event(s)"
          + (f", {span[0]} to {span[1]}" if span else ""))
    print("dates are as the sources gave them, not when NOVA read them.\n")
    for when, what, source in line.rows(args.limit):
        print(f"  {when:<11} {what}  ({source})")
    if line.dormant:
        print("\nquiet since:")
        for who, days in line.dormant[:10]:
            print(f"  {who}: {days:.0f} days before this scan")
    if line.clustered:
        print("\ncreated close together - a question, not a conclusion:")
        for a, b, gap in line.clustered[:10]:
            print(f"  {a} and {b}: {gap:.1f} day(s) apart")
    return EXIT_OK


def cmd_contradictions(args: argparse.Namespace, store: CaseStore) -> int:
    """Everything in a saved case that disagrees with something else in it."""
    inv = _case_or_fail(store, args.case)
    if inv is None:
        return EXIT_USAGE
    found = inv.contradictions
    if args.format == "json":
        print(json.dumps([c.to_dict() for c in found], indent=2, default=str))
        return EXIT_OK if found else EXIT_NO_FINDINGS
    if not found:
        print("nothing in this case contradicts anything else in it.")
        print("that is not the same as everything agreeing: see `nova show "
              f"{args.case}` for what was never checked.")
        return EXIT_NO_FINDINGS
    print(f"{len(found)} contradiction(s) in {inv.target}\n")
    print(reporting.CONTRADICTION_KEY + "\n")
    for clash in found:
        print(f"[{clash.severity.value}] {clash.type.value}: {clash.subject}")
        print(f"  {clash.summary}")
        for claim in clash.claims:
            print(f"    - {claim.value}  ({claim.source})"
                  + (f"  {claim.url}" if claim.url else ""))
        print("  could be:")
        for why in clash.possible_explanations:
            print(f"    . {why}")
        print(f"  status: {clash.resolution_status.value}\n")
    return EXIT_OK


def cmd_pivots(args: argparse.Namespace, store: CaseStore) -> int:
    """What is worth looking at next in a saved case, best first.

    Ranked by graph relevance rather than by the order modules happened to
    report them, and it says out loud which leads were found and deliberately
    *not* followed - a decision the reader cannot see is indistinguishable
    from a source that was never checked.
    """
    inv = _case_or_fail(store, args.case)
    if inv is None:
        return EXIT_USAGE
    graph = inv.graph
    #: ``value -> (relevance, kind, reason)``. Two sources feed it, and the
    #: graph is the better one: ``inv.pivots`` is the legacy flat list a module
    #: writes by hand, while the frontier is the actual pivot engine - scored,
    #: hub-demoted, and already excluding what was ruled out. A case whose
    #: modules all emit typed entities has a rich frontier and no pivot rows at
    #: all, so reading only the list reports "no leads" on a graph full of them.
    ranked: dict[str, tuple[float, str, str]] = {}
    if graph is not None:
        # Every bound relaxed on purpose: this is a listing, not a walk, and a
        # reader asking what is left wants the weak leads named and ranked last
        # rather than silently withheld. The seed is the one exclusion - a
        # pivot back to what was just scanned re-runs the scan.
        for node in graph.frontier(min_score=0.0, max_depth=99):
            if node.entity.eid == graph.seed:
                continue
            reason = "connected to the target"
            if node.corroborations:
                reason = f"{node.corroborations} independent source(s)"
            ranked[node.entity.display] = (node.score,
                                           node.entity.etype.value, reason)
    for pivot in inv.pivots:
        existing = ranked.get(pivot.target)
        if existing is None:
            ranked[pivot.target] = (0.0, pivot.target_type.value, pivot.reason)
        else:
            # Keep the graph's score, take the module's own words for why.
            ranked[pivot.target] = (existing[0], existing[1], pivot.reason)
    rows = sorted(((score, value, kind, reason)
                   for value, (score, kind, reason) in ranked.items()),
                  key=lambda row: (-row[0], row[1]))

    if args.format == "json":
        print(json.dumps([{
            "value": value, "type": kind, "relevance": round(score, 4),
            "reason": reason,
        } for score, value, kind, reason in rows], indent=2, default=str))
        return EXIT_OK if rows else EXIT_NO_FINDINGS
    if not rows:
        print("no unexplored leads were recorded for this case.")
        return EXIT_NO_FINDINGS
    print(f"{len(rows)} lead(s) from {inv.target}, most relevant first\n")
    for score, value, kind, reason in rows[:args.limit]:
        print(f"  {score:5.3f}  {value}  ({kind})  - {reason}")
    contradicted = graph.contradicted() if graph is not None else []
    if contradicted:
        print("\nfound and ruled out - the evidence argues against these:")
        for node in contradicted[:10]:
            print(f"  {node.entity.display}  "
                  f"({node.against:+.2f} against, {node.support:+.2f} for)")
    return EXIT_OK


def cmd_graph(args: argparse.Namespace, store: CaseStore) -> int:
    """Export a saved case's graph, or print it."""
    from pathlib import Path

    inv = _case_or_fail(store, args.case)
    if inv is None:
        return EXIT_USAGE
    renderer = reporting.RENDERERS.get(args.format)
    if renderer is None:
        print(f"unknown format: {args.format}", file=sys.stderr)
        return EXIT_USAGE
    rendered = renderer(inv)
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, "utf-8")
        print(f"wrote {path}")
        return EXIT_OK
    print(rendered)
    return EXIT_OK


def summarise_for_terminal(store: CaseStore, case_id: str) -> str:
    """One line a scan can print after saving, so the case id is never lost."""
    record = store.case(case_id)
    if record is None:
        return ""
    return (f"saved as case {record.id}  "
            f"(nova show {record.id[:8]} | nova diff {record.target})")


def open_store(path: Any = None) -> CaseStore:
    return CaseStore(path)


def elapsed(started: float) -> str:
    return f"{time.time() - started:.1f}s"


__all__ = [
    "PROBES", "cmd_diff", "cmd_doctor", "cmd_evidence", "cmd_history", "cmd_link",
    "cmd_phone", "cmd_replay", "cmd_show", "cmd_where", "open_store", "reporting",
    "summarise_for_terminal",
]
