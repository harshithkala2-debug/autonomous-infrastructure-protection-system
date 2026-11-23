"""Durable state of the agent guard: call history, freezes, tainted sessions and file checkpoints.

Everything lives in one SQLite file plus a content-addressed blob directory, so the guard works the same
when it is embedded in a long-running AIPS process and when it runs as a short-lived hook process per tool
call (Claude Code starts a new process for every hook). ``":memory:"`` keeps everything in memory (tests,
simulator); blobs then live in a temporary directory.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS calls (
    call_id TEXT PRIMARY KEY, agent TEXT NOT NULL, session TEXT, ts REAL NOT NULL, tool TEXT NOT NULL,
    intent TEXT NOT NULL, args TEXT NOT NULL, fingerprint TEXT NOT NULL, verdict TEXT NOT NULL, risk REAL NOT NULL,
    reasons TEXT NOT NULL, flagged INTEGER NOT NULL, executed INTEGER NOT NULL DEFAULT 0, success INTEGER,
    result_ts REAL, reverted INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS calls_agent_ts ON calls(agent, ts);
CREATE INDEX IF NOT EXISTS calls_session ON calls(session, ts);
CREATE TABLE IF NOT EXISTS frozen (agent TEXT PRIMARY KEY, reason TEXT, at REAL, by TEXT);
CREATE TABLE IF NOT EXISTS taint (session TEXT PRIMARY KEY, at REAL, reason TEXT);
CREATE TABLE IF NOT EXISTS checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT, call_id TEXT NOT NULL, agent TEXT NOT NULL, ts REAL NOT NULL,
    path TEXT NOT NULL, existed INTEGER NOT NULL, blob TEXT, size INTEGER, restored INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS ckpt_call ON checkpoints(call_id);
CREATE TABLE IF NOT EXISTS reverts (
    id TEXT PRIMARY KEY, agent TEXT NOT NULL, ts REAL NOT NULL, by TEXT, entries TEXT NOT NULL,
    undone INTEGER NOT NULL DEFAULT 0);
"""


@dataclass
class CallRow:
    call_id: str
    agent: str
    session: str | None
    ts: float
    tool: str
    intent: str
    args: dict[str, Any]
    fingerprint: str
    verdict: str
    risk: float
    reasons: list[str]
    flagged: bool
    executed: bool
    success: bool | None
    reverted: bool


@dataclass
class CheckpointRow:
    id: int
    call_id: str
    agent: str
    ts: float
    path: str
    existed: bool
    blob: str | None
    size: int | None
    restored: bool


class AgentStore:
    def __init__(self, path: str | Path = ":memory:", blob_dir: str | Path | None = None):
        self.path = str(path)
        if blob_dir is None:
            blob_dir = (Path(tempfile.mkdtemp(prefix="aips-agent-blobs-")) if self.path == ":memory:"
                        else Path(self.path).with_name("blobs"))
        self.blob_dir = Path(blob_dir)
        self.blob_dir.mkdir(parents=True, exist_ok=True)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path, timeout=10.0, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        if self.path != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)
        self._lock = threading.RLock()

    def close(self) -> None:
        self._db.close()

    # -- calls ---------------------------------------------------------------------------------------------
    def add_call(self, row: CallRow) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO calls VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (row.call_id, row.agent, row.session, row.ts, row.tool, row.intent, json.dumps(row.args, default=str),
                 row.fingerprint, row.verdict, row.risk, json.dumps(row.reasons), int(row.flagged), int(row.executed),
                 None if row.success is None else int(row.success), None, int(row.reverted)))

    def set_result(self, call_id: str, success: bool, ts: float) -> bool:
        with self._lock:
            cur = self._db.execute("UPDATE calls SET executed=1, success=?, result_ts=? WHERE call_id=?",
                                   (int(success), ts, call_id))
            return cur.rowcount > 0

    def flag_call(self, call_id: str, reason: str) -> None:
        with self._lock:
            r = self._db.execute("SELECT reasons FROM calls WHERE call_id=?", (call_id,)).fetchone()
            if r is None:
                return
            reasons = json.loads(r["reasons"]) + [reason]
            self._db.execute("UPDATE calls SET flagged=1, reasons=? WHERE call_id=?", (json.dumps(reasons), call_id))

    def get_call(self, call_id: str) -> CallRow | None:
        r = self._db.execute("SELECT * FROM calls WHERE call_id=?", (call_id,)).fetchone()
        return _call(r) if r else None

    def calls(self, agent: str | None = None, since: float = 0.0, session: str | None = None,
              limit: int = 5000) -> list[CallRow]:
        q, args = "SELECT * FROM calls WHERE ts >= ?", [since]
        if agent is not None:
            q += " AND agent = ?"
            args.append(agent)
        if session is not None:
            q += " AND session = ?"
            args.append(session)
        q += " ORDER BY ts, rowid LIMIT ?"
        args.append(limit)
        return [_call(r) for r in self._db.execute(q, args)]

    def count(self, agent: str, since: float, verdicts: tuple[str, ...] | None = None,
              fingerprint: str | None = None) -> int:
        q, args = "SELECT COUNT(*) FROM calls WHERE agent=? AND ts>=?", [agent, since]
        if verdicts:
            q += f" AND verdict IN ({','.join('?' * len(verdicts))})"
            args += list(verdicts)
        if fingerprint:
            q += " AND fingerprint=?"
            args.append(fingerprint)
        return int(self._db.execute(q, args).fetchone()[0])

    def recent_results(self, agent: str, n: int) -> list[bool]:
        rows = self._db.execute("SELECT success FROM calls WHERE agent=? AND executed=1 ORDER BY result_ts DESC "
                                "LIMIT ?", (agent, n)).fetchall()
        return [bool(r[0]) for r in rows]

    def session_calls(self, session: str) -> int:
        return int(self._db.execute("SELECT COUNT(*) FROM calls WHERE session=?", (session,)).fetchone()[0])

    def agents(self) -> list[str]:
        return [r[0] for r in self._db.execute("SELECT DISTINCT agent FROM calls ORDER BY agent")]

    def mark_reverted(self, call_ids: list[str], value: bool = True) -> None:
        with self._lock:
            self._db.executemany("UPDATE calls SET reverted=? WHERE call_id=?", [(int(value), c) for c in call_ids])

    # -- freeze / taint ------------------------------------------------------------------------------------
    def freeze(self, agent: str, reason: str, at: float, by: str) -> None:
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO frozen VALUES (?,?,?,?)", (agent, reason, at, by))

    def unfreeze(self, agent: str) -> bool:
        with self._lock:
            return self._db.execute("DELETE FROM frozen WHERE agent=?", (agent,)).rowcount > 0

    def frozen(self) -> dict[str, dict[str, Any]]:
        return {r["agent"]: {"reason": r["reason"], "at": r["at"], "by": r["by"]}
                for r in self._db.execute("SELECT * FROM frozen")}

    def is_frozen(self, agent: str) -> bool:
        return self._db.execute("SELECT 1 FROM frozen WHERE agent=?", (agent,)).fetchone() is not None

    def taint(self, session: str, at: float, reason: str) -> None:
        with self._lock:
            self._db.execute("INSERT OR IGNORE INTO taint VALUES (?,?,?)", (session, at, reason))

    def tainted(self, session: str | None) -> str | None:
        if not session:
            return None
        r = self._db.execute("SELECT reason FROM taint WHERE session=?", (session,)).fetchone()
        return r[0] if r else None

    def clear_taint(self, session: str) -> bool:
        with self._lock:
            return self._db.execute("DELETE FROM taint WHERE session=?", (session,)).rowcount > 0

    # -- checkpoints ---------------------------------------------------------------------------------------
    def put_blob(self, data: bytes) -> str:
        sha = hashlib.sha256(data).hexdigest()
        p = self.blob_dir / sha[:2] / sha
        if not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(".tmp")
            tmp.write_bytes(data)
            tmp.replace(p)
        return sha

    def get_blob(self, sha: str) -> bytes:
        data = (self.blob_dir / sha[:2] / sha).read_bytes()
        if hashlib.sha256(data).hexdigest() != sha:
            raise ValueError(f"checkpoint blob {sha[:12]} is corrupted")
        return data

    def add_checkpoint(self, call_id: str, agent: str, ts: float, path: str, existed: bool,
                       blob: str | None, size: int | None) -> None:
        with self._lock:
            self._db.execute("INSERT INTO checkpoints (call_id, agent, ts, path, existed, blob, size) "
                             "VALUES (?,?,?,?,?,?,?)", (call_id, agent, ts, path, int(existed), blob, size))

    def checkpoints(self, call_id: str | None = None, agent: str | None = None) -> list[CheckpointRow]:
        q, args = "SELECT * FROM checkpoints WHERE 1=1", []
        if call_id:
            q += " AND call_id=?"
            args.append(call_id)
        if agent:
            q += " AND agent=?"
            args.append(agent)
        return [CheckpointRow(r["id"], r["call_id"], r["agent"], r["ts"], r["path"], bool(r["existed"]), r["blob"],
                              r["size"], bool(r["restored"])) for r in self._db.execute(q + " ORDER BY id", args)]

    def mark_restored(self, ids: list[int], value: bool = True) -> None:
        with self._lock:
            self._db.executemany("UPDATE checkpoints SET restored=? WHERE id=?", [(int(value), i) for i in ids])

    # -- reverts (so a revert can itself be undone) ---------------------------------------------------------
    def add_revert(self, rid: str, agent: str, ts: float, by: str, entries: list[dict[str, Any]]) -> None:
        with self._lock:
            self._db.execute("INSERT INTO reverts VALUES (?,?,?,?,?,0)", (rid, agent, ts, by, json.dumps(entries)))

    def get_revert(self, rid: str) -> dict[str, Any] | None:
        r = self._db.execute("SELECT * FROM reverts WHERE id=?", (rid,)).fetchone()
        if r is None:
            return None
        return {"id": r["id"], "agent": r["agent"], "ts": r["ts"], "by": r["by"],
                "entries": json.loads(r["entries"]), "undone": bool(r["undone"])}

    def mark_revert_undone(self, rid: str) -> None:
        with self._lock:
            self._db.execute("UPDATE reverts SET undone=1 WHERE id=?", (rid,))

    def stats(self) -> dict[str, Any]:
        verdicts = dict(self._db.execute("SELECT verdict, COUNT(*) FROM calls GROUP BY verdict").fetchall())
        return {"calls": sum(verdicts.values()), "verdicts": verdicts, "frozen": len(self.frozen()),
                "checkpoints": int(self._db.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0]),
                "tainted_sessions": int(self._db.execute("SELECT COUNT(*) FROM taint").fetchone()[0])}

    def __iter__(self) -> Iterator[CallRow]:
        return iter(self.calls())


def _call(r: sqlite3.Row) -> CallRow:
    return CallRow(r["call_id"], r["agent"], r["session"], r["ts"], r["tool"], r["intent"], json.loads(r["args"]),
                   r["fingerprint"], r["verdict"], r["risk"], json.loads(r["reasons"]), bool(r["flagged"]),
                   bool(r["executed"]), None if r["success"] is None else bool(r["success"]), bool(r["reverted"]))
