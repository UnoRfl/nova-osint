"""Case storage: what was found, what it was found from, and proof of both.

Until now every scan was fire-and-forget. That is enough to answer "what is true
about this target", and useless for the two questions that make a tool worth
keeping: *what changed since last time*, and *how do you know*.

Three stores, one directory:

``cases.db``
    SQLite. One row per case, plus its entities, edges, observations and
    findings. Normalised enough to query across cases - "which other
    investigation has seen this email" is one ``SELECT``.

``evidence/``
    Content-addressed raw responses, ``sha256[:2]/sha256``, gzipped. A finding
    references the digest of the bytes it was parsed from, so it stays checkable
    after the source changes its mind or disappears. Deduplicated for free: two
    cases that fetched the same unchanged page store one copy.

``audit.log``
    Hash-chained, append-only. Each line carries the hash of the line before it,
    so a deleted or edited entry breaks the chain at a detectable point. This is
    not cryptographic proof against someone who controls the file - it is proof
    the file has not been *casually* edited, which is the threat that actually
    occurs.

Design constraints worth not re-deciding
----------------------------------------

* **Stdlib only.** ``sqlite3`` ships with Python; the engine stays installable
  on a locked-down box, which was the whole point of the urllib decision.
* **Writes go through one connection on one thread.** SQLite tolerates more than
  that, but the engine is already running two thread pools and a WAL-mode
  database being written from module threads is a lock-contention bug waiting
  to be blamed on the network. The engine collects, then persists.
* **Nothing here ever raises into a scan.** A failed write degrades to a warning.
  Losing the record of a scan is bad; losing the scan is worse.
* **The schema is versioned from day one** (``PRAGMA user_version``) because the
  first migration always arrives sooner than expected.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .entities import Entity, EntityType
from .graph import EntityGraph, Observation
from .logging_config import get_logger
from .models import Finding, Investigation

log = get_logger("store")

DEFAULT_CASE_DIR = Path.home() / ".local" / "share" / "nova-osint"

SCHEMA_VERSION = 3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id            TEXT PRIMARY KEY,
    target        TEXT NOT NULL,
    target_type   TEXT NOT NULL,
    seed_eid      TEXT,
    started_at    REAL NOT NULL,
    finished_at   REAL,
    duration      REAL,
    label         TEXT DEFAULT '',
    config_hash   TEXT DEFAULT '',
    nova_version  TEXT DEFAULT '',
    summary       TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS cases_target ON cases(target, started_at DESC);

CREATE TABLE IF NOT EXISTS entities (
    case_id    TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    eid        TEXT NOT NULL,
    etype      TEXT NOT NULL,
    value      TEXT NOT NULL,
    raw        TEXT DEFAULT '',
    score      REAL DEFAULT 0,
    depth      INTEGER DEFAULT 0,
    expanded   INTEGER DEFAULT 0,
    sources    TEXT DEFAULT '[]',
    attrs      TEXT DEFAULT '{}',
    PRIMARY KEY (case_id, eid)
);
-- The cross-case index. Without it "who else has seen this address" is a table
-- scan over every entity ever recorded.
CREATE INDEX IF NOT EXISTS entities_value ON entities(etype, value);

CREATE TABLE IF NOT EXISTS edges (
    case_id  TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    src      TEXT NOT NULL,
    dst      TEXT NOT NULL,
    label    TEXT NOT NULL,
    llr      REAL DEFAULT 0,
    grade    TEXT DEFAULT '',
    PRIMARY KEY (case_id, src, dst, label)
);
CREATE INDEX IF NOT EXISTS edges_src ON edges(case_id, src);

CREATE TABLE IF NOT EXISTS observations (
    case_id   TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    src       TEXT NOT NULL,
    dst       TEXT NOT NULL,
    label     TEXT NOT NULL,
    kind      TEXT NOT NULL,
    module    TEXT NOT NULL,
    url       TEXT,
    detail    TEXT DEFAULT '',
    evidence  TEXT,
    llr       REAL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS observations_edge ON observations(case_id, src, dst);

CREATE TABLE IF NOT EXISTS findings (
    case_id     TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    fid         TEXT NOT NULL,
    module      TEXT NOT NULL,
    label       TEXT NOT NULL,
    value       TEXT NOT NULL,
    source      TEXT NOT NULL,
    confidence  TEXT NOT NULL,
    severity    TEXT NOT NULL,
    url         TEXT,
    entity      TEXT,
    evidence    TEXT,
    extra       TEXT DEFAULT '{}',
    PRIMARY KEY (case_id, fid)
);
CREATE INDEX IF NOT EXISTS findings_module ON findings(case_id, module);

CREATE TABLE IF NOT EXISTS statuses (
    case_id  TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    module   TEXT NOT NULL,
    status   TEXT NOT NULL,
    reason   TEXT DEFAULT '',
    duration REAL DEFAULT 0,
    PRIMARY KEY (case_id, module)
);

-- What was fetched, when, and what came back. Separate from findings on
-- purpose: a request that produced nothing is still part of the record, and
-- "we looked and the source was down" is exactly the thing reports lose.
CREATE TABLE IF NOT EXISTS requests (
    case_id   TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    at        REAL NOT NULL,
    module    TEXT DEFAULT '',
    method    TEXT DEFAULT 'GET',
    url       TEXT NOT NULL,
    status    INTEGER,
    access    TEXT DEFAULT '',
    bytes     INTEGER DEFAULT 0,
    elapsed   REAL DEFAULT 0,
    digest    TEXT,
    -- Kept so `nova replay` can rebuild a Response faithfully; a parser that
    -- reads a header would otherwise see an empty dict on replay and the
    -- regression the replay exists to catch would be invisible.
    headers   TEXT DEFAULT '{}',
    -- Where the request actually landed. Differs from url whenever a source
    -- redirects (rdap.org hands off to the registry), and both are worth
    -- keeping: one is what we asked, the other is who answered.
    final_url TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS requests_case ON requests(case_id, at);
"""


def finding_id(module: str, f: Finding) -> str:
    """Stable identity for a finding, across runs.

    Diffing is the reason this exists. Two scans a week apart must agree that
    "mail exchangers -> [...]" is the same finding so a change registers as a
    change rather than as one removal and one addition. The value is *not* in
    the key for that reason; the module, label, source and url are.
    """
    key = "|".join([module, f.label.casefold(), f.source.casefold(), (f.url or "").casefold()])
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _value_text(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        return json.dumps(sorted(str(v) for v in value))
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return str(value)


# ---------------------------------------------------------------------------
# evidence
# ---------------------------------------------------------------------------


def _discard(path: Path | None) -> None:
    """Remove a temp file, ignoring the case where it is already gone."""
    if path is None:
        return
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


class EvidenceStore:
    """Content-addressed store of raw response bodies.

    Content addressing is doing real work here, not being clever: the digest is
    both the filename and the integrity check, two scans of an unchanged page
    cost one copy, and a finding that cites a digest can be re-verified by
    anyone holding the directory - no index to trust, no database to agree with.
    """

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def put(self, data: bytes | str) -> str | None:
        """Store bytes, return the sha256 hex digest. ``None`` if it could not."""
        if isinstance(data, str):
            data = data.encode("utf-8", "replace")
        if not data:
            return None
        digest = hashlib.sha256(data).hexdigest()
        path = self._path(digest)
        if path.exists():
            return digest
        tmp = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Write to a temporary name and rename: a half-written evidence file
            # whose name claims a digest it does not hash to is worse than none.
            #
            # The temp name carries the writer's identity. Two threads storing
            # the *same* bytes is normal - single-flight shares the response but
            # each module's recorder files it - and with a shared ".part" name
            # they raced: one renamed it out from under the other, whose replace
            # then failed on Windows and dropped the body. The finding survived
            # and its evidence quietly did not, which is the worst shape a bug
            # in this file can take.
            tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.part")
            with gzip.open(tmp, "wb", compresslevel=6) as fh:
                fh.write(data)
            os.replace(tmp, path)
        except OSError as exc:
            # Content-addressed: if it is already there, someone else won the
            # race and wrote the identical bytes. That is success, not failure.
            if path.exists():
                _discard(tmp)
                return digest
            log.warning("could not store evidence %s: %s", digest[:12], exc)
            _discard(tmp)
            return None
        return digest

    def get(self, digest: str) -> bytes | None:
        path = self._path(digest)
        if not path.exists():
            return None
        try:
            with gzip.open(path, "rb") as fh:
                return fh.read()
        except OSError as exc:
            log.warning("could not read evidence %s: %s", digest[:12], exc)
            return None

    def verify(self, digest: str) -> bool:
        """Re-hash the stored bytes. A silent bit-flip is the point of doing this."""
        data = self.get(digest)
        return data is not None and hashlib.sha256(data).hexdigest() == digest

    def _path(self, digest: str) -> Path:
        # Two-character fan-out: 256 directories keeps any one of them small
        # enough that a directory listing on Windows stays usable.
        return self.root / digest[:2] / digest

    def size(self) -> tuple[int, int]:
        """``(files, bytes on disk)``."""
        count = total = 0
        if not self.root.exists():
            return (0, 0)
        for p in self.root.rglob("*"):
            if p.is_file() and p.suffix != ".part":
                count += 1
                total += p.stat().st_size
        return count, total


# ---------------------------------------------------------------------------
# audit log
# ---------------------------------------------------------------------------


class AuditLog:
    """Append-only, hash-chained record of what this tool was pointed at.

    Every line is ``{"prev": <hash of previous line>, ...}``. Deleting or
    editing a line breaks the chain from that point on, which :meth:`verify`
    reports by index. Chosen over a signature because a signature needs a key to
    protect, and an unprotected key would make the guarantee a decoration.
    """

    GENESIS = "0" * 64

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def append(self, action: str, **fields: Any) -> str:
        entry = {"at": round(time.time(), 3), "action": action, **fields}
        entry["prev"] = self._last_hash()
        line = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(line.encode()).hexdigest()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError as exc:
            log.warning("audit log write failed: %s", exc)
        return digest

    def _last_hash(self) -> str:
        last = None
        for line in self._lines():
            last = line
        if last is None:
            return self.GENESIS
        return hashlib.sha256(last.encode()).hexdigest()

    def _lines(self) -> Iterator[str]:
        if not self.path.exists():
            return
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        yield line
        except OSError as exc:
            log.warning("audit log read failed: %s", exc)

    def verify(self) -> tuple[bool, int]:
        """``(intact, entries checked)``; on failure the int is the bad index."""
        prev = self.GENESIS
        for i, line in enumerate(self._lines()):
            try:
                entry = json.loads(line)
            except ValueError:
                return (False, i)
            if entry.get("prev") != prev:
                return (False, i)
            prev = hashlib.sha256(line.encode()).hexdigest()
        return (True, sum(1 for _ in self._lines()))

    def entries(self, limit: int = 50) -> list[dict[str, Any]]:
        out = []
        for line in self._lines():
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out[-limit:]


# ---------------------------------------------------------------------------
# case records
# ---------------------------------------------------------------------------


@dataclass
class CaseRecord:
    id: str
    target: str
    target_type: str
    started_at: float
    duration: float
    label: str = ""
    summary: dict[str, Any] | None = None

    @property
    def when(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(self.started_at))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "target": self.target, "target_type": self.target_type,
            "started_at": self.started_at, "when": self.when,
            "duration": round(self.duration, 2), "label": self.label,
            "summary": self.summary or {},
        }


@dataclass
class Change:
    """One difference between two cases."""

    kind: str          # added | removed | changed
    scope: str         # finding | entity | edge | status
    key: str
    before: Any = None
    after: Any = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "scope": self.scope, "key": self.key,
                "before": self.before, "after": self.after, "detail": self.detail}


# ---------------------------------------------------------------------------
# the store
# ---------------------------------------------------------------------------


class CaseStore:
    """SQLite-backed history of every investigation."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = Path(root or DEFAULT_CASE_DIR)
        self.root.mkdir(parents=True, exist_ok=True)
        self.evidence = EvidenceStore(self.root / "evidence")
        self.audit = AuditLog(self.root / "audit.log")
        self.db_path = self.root / "cases.db"
        self._conn: sqlite3.Connection | None = None

    # -- connection ----------------------------------------------------------

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, timeout=10.0)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._migrate(self._conn)
        return self._conn

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version == 0:
            conn.executescript(_SCHEMA)
            conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            conn.commit()
        elif version < SCHEMA_VERSION:
            for step in range(version + 1, SCHEMA_VERSION + 1):
                _MIGRATIONS[step](conn)
                conn.execute(f"PRAGMA user_version={step}")
            conn.commit()
            log.info("migrated case store from schema v%d to v%d", version, SCHEMA_VERSION)
        elif version > SCHEMA_VERSION:
            # Refuse rather than corrupt: a newer NOVA wrote this file and we do
            # not know what it added.
            raise RuntimeError(
                f"case store is schema v{version}, this NOVA understands v{SCHEMA_VERSION}"
            )

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        conn = self.conn
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> CaseStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- writing -------------------------------------------------------------

    def save(self, inv: Investigation, graph: EntityGraph | None = None, *,
             case_id: str | None = None, label: str = "",
             requests: list[dict[str, Any]] | None = None) -> str:
        """Persist a finished investigation. Returns the case id.

        Never raises into the caller: a scan that completed and could not be
        filed is still a scan the user wants to read.
        """
        cid = case_id or self.new_case_id(inv.target, inv.started_at)
        try:
            with self._tx() as conn:
                self._write_case(conn, cid, inv, graph, label)
                self._write_findings(conn, cid, inv, graph)
                self._write_graph(conn, cid, graph)
                self._write_requests(conn, cid, requests or [])
        except Exception as exc:  # pragma: no cover - disk/permission territory
            log.warning("could not save case %s: %s", cid, exc)
            return cid
        self.audit.append("scan", case=cid, target=inv.target,
                          target_type=inv.target_type.value,
                          findings=len(inv.findings),
                          modules=[r.module for r in inv.results])
        return cid

    @staticmethod
    def new_case_id(target: str, when: float) -> str:
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(when))
        short = hashlib.sha256(target.encode()).hexdigest()[:6]
        return f"{stamp}-{short}"

    def _write_case(self, conn: sqlite3.Connection, cid: str, inv: Investigation,
                    graph: EntityGraph | None, label: str) -> None:
        from .. import __version__

        summary = inv.to_dict()["summary"]
        if graph is not None:
            summary["entities"] = len(graph)
            summary["edges"] = len(graph.edges)
        conn.execute(
            "INSERT OR REPLACE INTO cases "
            "(id,target,target_type,seed_eid,started_at,finished_at,duration,label,"
            " nova_version,summary) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (cid, inv.target, inv.target_type.value,
             graph.seed if graph else None, inv.started_at, inv.finished_at,
             inv.duration, label, __version__, json.dumps(summary)),
        )
        conn.executemany(
            "INSERT OR REPLACE INTO statuses (case_id,module,status,reason,duration) "
            "VALUES (?,?,?,?,?)",
            [(cid, r.module, r.status.value, r.status_reason, r.duration)
             for r in inv.results],
        )
        conn.executemany(
            "INSERT OR REPLACE INTO statuses (case_id,module,status,reason,duration) "
            "VALUES (?,?,?,?,?)",
            [(cid, name, "skipped", reason, 0.0) for name, reason in inv.skipped],
        )

    def _write_findings(self, conn: sqlite3.Connection, cid: str, inv: Investigation,
                        graph: EntityGraph | None) -> None:
        rows = []
        for result in inv.results:
            for f in result.findings:
                rows.append((
                    cid, finding_id(result.module, f), result.module, f.label,
                    _value_text(f.value), f.source, f.confidence.value,
                    f.severity.value, f.url, f.extra.get("entity"),
                    f.extra.get("evidence"), json.dumps(f.extra, default=str),
                ))
        conn.executemany(
            "INSERT OR REPLACE INTO findings "
            "(case_id,fid,module,label,value,source,confidence,severity,url,entity,"
            " evidence,extra) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)

    def _write_graph(self, conn: sqlite3.Connection, cid: str,
                     graph: EntityGraph | None) -> None:
        if graph is None:
            return
        conn.executemany(
            "INSERT OR REPLACE INTO entities "
            "(case_id,eid,etype,value,raw,score,depth,expanded,sources,attrs) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            [(cid, n.entity.eid, n.entity.etype.value, n.entity.value, n.entity.raw,
              n.score, n.depth, int(n.expanded), json.dumps(sorted(n.sources)),
              json.dumps(n.entity.attrs, default=str)) for n in graph],
        )
        conn.executemany(
            "INSERT OR REPLACE INTO edges (case_id,src,dst,label,llr,grade) "
            "VALUES (?,?,?,?,?,?)",
            [(cid, e.src, e.dst, e.label, e.llr, e.grade) for e in graph.edges.values()],
        )
        conn.execute("DELETE FROM observations WHERE case_id=?", (cid,))
        conn.executemany(
            "INSERT INTO observations "
            "(case_id,src,dst,label,kind,module,url,detail,evidence,llr) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            [(cid, e.src, e.dst, e.label, o.kind, o.module, o.url, o.detail,
              o.evidence, o.strength)
             for e in graph.edges.values() for o in e.observations],
        )

    def _write_requests(self, conn: sqlite3.Connection, cid: str,
                        requests: list[dict[str, Any]]) -> None:
        conn.executemany(
            "INSERT INTO requests "
            "(case_id,at,module,method,url,status,access,bytes,elapsed,digest,"
            " headers,final_url) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            [(cid, r.get("at", 0.0), r.get("module", ""), r.get("method", "GET"),
              r.get("url", ""), r.get("status"), r.get("access", ""),
              r.get("bytes", 0), r.get("elapsed", 0.0), r.get("digest"),
              json.dumps(r.get("headers") or {}), r.get("final_url", ""))
             for r in requests],
        )

    # -- reading -------------------------------------------------------------

    def cases(self, target: str | None = None, limit: int = 25) -> list[CaseRecord]:
        sql = "SELECT * FROM cases"
        args: tuple[Any, ...] = ()
        if target:
            sql += " WHERE target = ?"
            args = (target,)
        sql += " ORDER BY started_at DESC LIMIT ?"
        rows = self.conn.execute(sql, (*args, limit)).fetchall()
        return [self._record(r) for r in rows]

    def case(self, cid: str) -> CaseRecord | None:
        row = self.conn.execute("SELECT * FROM cases WHERE id = ?", (cid,)).fetchone()
        if row is None:
            # Accept an unambiguous prefix; case ids are long and typed by hand.
            rows = self.conn.execute(
                "SELECT * FROM cases WHERE id LIKE ? LIMIT 2", (cid + "%",)).fetchall()
            if len(rows) == 1:
                row = rows[0]
        return self._record(row) if row else None

    def latest(self, target: str) -> CaseRecord | None:
        cases = self.cases(target=target, limit=1)
        return cases[0] if cases else None

    @staticmethod
    def _record(row: sqlite3.Row) -> CaseRecord:
        return CaseRecord(
            id=row["id"], target=row["target"], target_type=row["target_type"],
            started_at=row["started_at"], duration=row["duration"] or 0.0,
            label=row["label"] or "",
            summary=json.loads(row["summary"] or "{}"),
        )

    def findings(self, cid: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM findings WHERE case_id = ? ORDER BY module, label",
            (cid,)).fetchall()

    def statuses(self, cid: str) -> dict[str, tuple[str, str]]:
        return {r["module"]: (r["status"], r["reason"])
                for r in self.conn.execute(
                    "SELECT * FROM statuses WHERE case_id = ?", (cid,))}

    def graph(self, cid: str) -> EntityGraph:
        """Rebuild the graph exactly as it was, with observations attached."""
        graph = EntityGraph()
        rows = self.conn.execute(
            "SELECT * FROM entities WHERE case_id = ?", (cid,)).fetchall()
        by_eid: dict[str, Entity] = {}
        for r in rows:
            try:
                etype = EntityType(r["etype"])
            except ValueError:
                etype = EntityType.UNKNOWN
            ent = Entity(etype, r["value"], r["raw"] or "",
                         json.loads(r["attrs"] or "{}"))
            by_eid[r["eid"]] = ent
            node = graph.add(ent, score=r["score"], depth=r["depth"])
            node.expanded = bool(r["expanded"])
            node.sources = set(json.loads(r["sources"] or "[]"))
        seed = self.conn.execute(
            "SELECT seed_eid FROM cases WHERE id = ?", (cid,)).fetchone()
        if seed and seed[0] in by_eid:
            graph.seed = seed[0]
        for o in self.conn.execute(
                "SELECT * FROM observations WHERE case_id = ?", (cid,)):
            src, dst = by_eid.get(o["src"]), by_eid.get(o["dst"])
            if src is None or dst is None:
                continue
            graph.connect(src, dst, o["label"], Observation(
                kind=o["kind"], module=o["module"], url=o["url"],
                detail=o["detail"] or "", evidence=o["evidence"], llr=o["llr"]))
        graph.rescore()
        return graph

    def requests(self, cid: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM requests WHERE case_id = ? ORDER BY at", (cid,)).fetchall()

    # -- analysis ------------------------------------------------------------

    def diff(self, old_id: str, new_id: str) -> list[Change]:
        """What changed between two cases. The reason the store exists.

        Findings are keyed by :func:`finding_id`, which excludes the value, so a
        record whose content moved shows up as ``changed`` with both sides
        rather than as an unexplained removal next to an unexplained addition.
        """
        changes: list[Change] = []
        old = {r["fid"]: r for r in self.findings(old_id)}
        new = {r["fid"]: r for r in self.findings(new_id)}

        for fid, row in new.items():
            if fid not in old:
                changes.append(Change("added", "finding", f"{row['module']}: {row['label']}",
                                      after=row["value"]))
            elif old[fid]["value"] != row["value"]:
                changes.append(Change("changed", "finding",
                                      f"{row['module']}: {row['label']}",
                                      before=old[fid]["value"], after=row["value"]))
        for fid, row in old.items():
            if fid not in new:
                changes.append(Change("removed", "finding",
                                      f"{row['module']}: {row['label']}",
                                      before=row["value"]))

        old_ents = {r["eid"] for r in self.conn.execute(
            "SELECT eid FROM entities WHERE case_id = ?", (old_id,))}
        new_ents = {r["eid"] for r in self.conn.execute(
            "SELECT eid FROM entities WHERE case_id = ?", (new_id,))}
        for eid in sorted(new_ents - old_ents):
            changes.append(Change("added", "entity", eid))
        for eid in sorted(old_ents - new_ents):
            changes.append(Change("removed", "entity", eid))

        old_st, new_st = self.statuses(old_id), self.statuses(new_id)
        for module, (status, reason) in new_st.items():
            was = old_st.get(module, (None, ""))[0]
            if was is not None and was != status:
                # A module that used to work and now reports BLOCKED is a change
                # in *coverage*, not in the target, and reads as a false "removed"
                # finding unless it is called out on its own.
                changes.append(Change("changed", "status", module, before=was,
                                      after=status, detail=reason))
        changes.sort(key=lambda c: (c.scope, c.kind, c.key))
        return changes

    def link(self, a_id: str, b_id: str) -> list[dict[str, Any]]:
        """Entities two cases have in common - the cross-case correlation.

        No single scan can answer this, which is exactly why it is worth
        storing. Hub entities are included but flagged, because two unrelated
        sites sharing Cloudflare is not a link and the caller needs to be able
        to tell the difference without guessing.
        """
        rows = self.conn.execute(
            "SELECT a.eid, a.etype, a.value, a.score AS a_score, b.score AS b_score "
            "FROM entities a JOIN entities b ON a.eid = b.eid "
            "WHERE a.case_id = ? AND b.case_id = ? ORDER BY a.score + b.score DESC",
            (a_id, b_id)).fetchall()
        ga, gb = self.graph(a_id), self.graph(b_id)
        out = []
        for r in rows:
            degree = max(ga.degree(r["eid"]), gb.degree(r["eid"]))
            out.append({
                "eid": r["eid"], "type": r["etype"], "value": r["value"],
                "score": round((r["a_score"] + r["b_score"]) / 2, 4),
                "degree": degree,
                "shared_infrastructure": degree >= 12,
            })
        return out

    def seen_elsewhere(self, entity: Entity, exclude: str = "") -> list[CaseRecord]:
        """Every other case that has recorded this exact entity."""
        rows = self.conn.execute(
            "SELECT DISTINCT case_id FROM entities WHERE etype = ? AND value = ? "
            "AND case_id != ?", (entity.etype.value, entity.value, exclude)).fetchall()
        out = [self.case(r["case_id"]) for r in rows]
        return [c for c in out if c is not None]

    def forget(self, cid: str) -> bool:
        """Delete a case. Evidence blobs are kept - they may back another case."""
        with self._tx() as conn:
            cur = conn.execute("DELETE FROM cases WHERE id = ?", (cid,))
            for table in ("entities", "edges", "observations", "findings",
                          "statuses", "requests"):
                conn.execute(f"DELETE FROM {table} WHERE case_id = ?", (cid,))
        if cur.rowcount:
            self.audit.append("forget", case=cid)
        return bool(cur.rowcount)

    def stats(self) -> dict[str, Any]:
        c = self.conn
        files, size = self.evidence.size()
        intact, entries = self.audit.verify()
        return {
            "root": str(self.root),
            "cases": c.execute("SELECT COUNT(*) FROM cases").fetchone()[0],
            "entities": c.execute("SELECT COUNT(*) FROM entities").fetchone()[0],
            "findings": c.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
            "requests": c.execute("SELECT COUNT(*) FROM requests").fetchone()[0],
            "evidence_files": files,
            "evidence_bytes": size,
            "db_bytes": self.db_path.stat().st_size if self.db_path.exists() else 0,
            "audit_entries": entries if intact else -1,
            "audit_intact": intact,
        }


def _migrate_1_to_2(conn: sqlite3.Connection) -> None:
    """v2 keeps response headers, so a replay can rebuild the real Response."""
    conn.execute("ALTER TABLE requests ADD COLUMN headers TEXT DEFAULT '{}'")


def _migrate_2_to_3(conn: sqlite3.Connection) -> None:
    """v3 keeps the redirect target alongside the requested URL."""
    conn.execute("ALTER TABLE requests ADD COLUMN final_url TEXT DEFAULT ''")


#: Applied in order by :meth:`CaseStore._migrate`. A store two versions behind
#: runs both, so an old case directory keeps working instead of being refused.
_MIGRATIONS = {2: _migrate_1_to_2, 3: _migrate_2_to_3}
