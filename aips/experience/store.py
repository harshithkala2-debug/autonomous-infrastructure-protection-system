"""Experience store: AIPS's long-term memory (SQLite, standard library only).

Everything AIPS has lived through is kept across restarts:

* **episodes** - one row per attempt to resolve an incident with one
  strategy: asset, signal, category, severity, level, strategy, the actions
  taken, outcome (resolved / failed / relapsed / handed_off), reward,
  time to resolve, and the context it happened in;
* **actions** - every action of every episode with its result;
* **detector outcomes** - true/false-positive counts per detector and per
  finding fingerprint (the same interface as ``OutcomeMemory``, so Level 2's
  confidence calibration is persistent too);
* **notes** - free-form operator / system annotations (e.g. chronic issues).

It answers the questions other layers ask:

* "how often has this happened here lately?"      -> ``recurrence``
* "what happened the last times?"                 -> ``similar``
* "which strategy works best for this problem?"   -> ``strategy_stats``
* "how reliable is this detector?"                -> ``precision`` / ``confidence_factor``

Use ``":memory:"`` (default) for ephemeral runs or a file path to persist.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS episodes (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    run_id TEXT,
    asset TEXT NOT NULL,
    category TEXT NOT NULL,
    signal TEXT NOT NULL,
    severity TEXT,
    level TEXT,
    strategy TEXT NOT NULL,
    started_at REAL NOT NULL,
    ended_at REAL,
    outcome TEXT NOT NULL,
    reward REAL NOT NULL,
    attempt INTEGER,
    n_actions INTEGER,
    explored INTEGER DEFAULT 0,
    context TEXT
);
CREATE INDEX IF NOT EXISTS ix_ep_signal ON episodes(signal, strategy);
CREATE INDEX IF NOT EXISTS ix_ep_asset ON episodes(asset, signal, started_at);
CREATE TABLE IF NOT EXISTS actions (
    episode_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    kind TEXT NOT NULL,
    target TEXT,
    params TEXT,
    success INTEGER,
    dry_run INTEGER,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS detector_outcomes (
    key TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    tp INTEGER NOT NULL DEFAULT 0,
    fp INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS notes (
    at REAL NOT NULL,
    topic TEXT NOT NULL,
    text TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
"""

OUTCOMES = ("resolved", "failed", "relapsed", "handed_off", "superseded")


@dataclass
class Episode:
    id: str
    incident_id: str
    asset: str
    category: str
    signal: str
    strategy: str
    started_at: float
    outcome: str
    reward: float
    ended_at: float | None = None
    severity: str = ""
    level: str = ""
    attempt: int = 1
    n_actions: int = 0
    explored: bool = False
    run_id: str = ""
    context: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_s(self) -> float | None:
        return None if self.ended_at is None else self.ended_at - self.started_at


def reward_for(outcome: str, n_actions: int, duration_s: float | None) -> float:
    """Success is worth ~1; cheaper and faster successes are worth slightly more."""
    if outcome != "resolved":
        return {"relapsed": 0.2, "handed_off": 0.0, "failed": 0.0, "superseded": 0.0}.get(outcome, 0.0)
    cost = min(0.25, 0.03 * n_actions) + min(0.15, (duration_s or 0) / 3600)
    return round(1.0 - cost, 4)


class ExperienceStore:
    def __init__(self, path: str | Path = ":memory:", run_id: str = ""):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._db.executescript(SCHEMA)
            self._db.execute("INSERT OR IGNORE INTO meta(k, v) VALUES ('schema', '1')")
            self._db.commit()
        self.run_id = run_id

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ------------------------------------------------------------------ episodes
    def record_episode(self, ep: Episode, actions: list[dict[str, Any]] | None = None) -> None:
        if ep.outcome not in OUTCOMES:
            raise ValueError(f"unknown outcome {ep.outcome}")
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO episodes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ep.id, ep.incident_id, ep.run_id or self.run_id, ep.asset, ep.category, ep.signal, ep.severity,
                 ep.level, ep.strategy, ep.started_at, ep.ended_at, ep.outcome, ep.reward, ep.attempt,
                 ep.n_actions, int(ep.explored), json.dumps(ep.context, default=str)))
            self._db.execute("DELETE FROM actions WHERE episode_id = ?", (ep.id,))
            for i, a in enumerate(actions or []):
                self._db.execute("INSERT INTO actions VALUES (?,?,?,?,?,?,?,?)",
                                 (ep.id, i, a.get("kind"), a.get("target"), json.dumps(a.get("params", {}), default=str),
                                  int(bool(a.get("success"))), int(bool(a.get("dry_run"))), str(a.get("detail", ""))[:500]))
            self._db.commit()

    def mark_relapse(self, episode_id: str) -> None:
        """A resolution that did not hold: the strategy only bought time."""
        with self._lock:
            self._db.execute("UPDATE episodes SET outcome='relapsed', reward=? WHERE id=? AND outcome='resolved'",
                             (reward_for("relapsed", 0, None), episode_id))
            self._db.commit()

    def _row(self, r: sqlite3.Row) -> Episode:
        return Episode(r["id"], r["incident_id"], r["asset"], r["category"], r["signal"], r["strategy"],
                       r["started_at"], r["outcome"], r["reward"], r["ended_at"], r["severity"] or "",
                       r["level"] or "", r["attempt"] or 1, r["n_actions"] or 0, bool(r["explored"]),
                       r["run_id"] or "", json.loads(r["context"] or "{}"))

    def episodes(self, signal: str | None = None, asset: str | None = None, limit: int = 100) -> list[Episode]:
        q, args = "SELECT * FROM episodes WHERE 1=1", []
        if signal:
            q += " AND signal = ?"
            args.append(signal)
        if asset:
            q += " AND asset = ?"
            args.append(asset)
        q += " ORDER BY started_at DESC, id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            return [self._row(r) for r in self._db.execute(q, args).fetchall()]

    def actions(self, episode_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM actions WHERE episode_id=? ORDER BY seq", (episode_id,)).fetchall()
        return [dict(r) | {"params": json.loads(r["params"] or "{}")} for r in rows]

    def similar(self, signal: str, asset: str | None = None, limit: int = 5) -> list[dict[str, Any]]:
        """Most relevant past episodes: same signal, same asset first."""
        with self._lock:
            rows = self._db.execute(
                "SELECT *, (asset = ?) AS same_asset FROM episodes WHERE signal = ? "
                "ORDER BY same_asset DESC, started_at DESC LIMIT ?", (asset or "", signal, limit)).fetchall()
        return [{"episode": r["id"], "asset": r["asset"], "strategy": r["strategy"], "outcome": r["outcome"],
                 "reward": r["reward"], "duration_s": (r["ended_at"] - r["started_at"]) if r["ended_at"] else None}
                for r in rows]

    def recurrence(self, asset: str, signal: str, since: float) -> int:
        """Distinct incidents for this asset+signal since a timestamp."""
        with self._lock:
            return int(self._db.execute(
                "SELECT COUNT(DISTINCT incident_id) FROM episodes WHERE asset=? AND signal=? AND started_at >= ?",
                (asset, signal, since)).fetchone()[0])

    def strategy_stats(self, signal: str, asset: str | None = None) -> dict[str, dict[str, float]]:
        """Per strategy: trials, successes, mean reward, mean time to resolve. Asset-specific rows count double."""
        with self._lock:
            rows = self._db.execute(
                "SELECT strategy, asset, outcome, reward, started_at, ended_at FROM episodes "
                "WHERE signal = ? AND outcome != 'handed_off'", (signal,)).fetchall()
        out: dict[str, dict[str, float]] = {}
        for r in rows:
            w = 2.0 if asset and r["asset"] == asset else 1.0
            s = out.setdefault(r["strategy"], {"trials": 0.0, "weight": 0.0, "reward_sum": 0.0, "successes": 0.0,
                                               "ttr_sum": 0.0, "ttr_n": 0.0})
            s["trials"] += 1
            s["weight"] += w
            s["reward_sum"] += w * r["reward"]
            if r["outcome"] == "resolved":
                s["successes"] += 1
                if r["ended_at"]:
                    s["ttr_sum"] += r["ended_at"] - r["started_at"]
                    s["ttr_n"] += 1
        for s in out.values():
            s["mean_reward"] = round(s["reward_sum"] / s["weight"], 4) if s["weight"] else 0.0
            s["mean_ttr_s"] = round(s["ttr_sum"] / s["ttr_n"], 1) if s["ttr_n"] else None
        return out

    # ------------------------------------------------------------------ OutcomeMemory-compatible interface
    def record(self, fingerprint: str, detector: str, true_positive: bool) -> None:
        col = "tp" if true_positive else "fp"
        with self._lock:
            for key, scope in ((f"fp:{fingerprint}", "fingerprint"), (f"det:{detector}", "detector")):
                self._db.execute("INSERT OR IGNORE INTO detector_outcomes(key, scope) VALUES (?, ?)", (key, scope))
                self._db.execute(f"UPDATE detector_outcomes SET {col} = {col} + 1 WHERE key = ?", (key,))
            self._db.commit()

    def _counts(self, key: str) -> tuple[int, int]:
        with self._lock:
            r = self._db.execute("SELECT tp, fp FROM detector_outcomes WHERE key=?", (key,)).fetchone()
        return (r["tp"], r["fp"]) if r else (0, 0)

    def precision(self, fingerprint: str, detector: str) -> float:
        ftp, ffp = self._counts(f"fp:{fingerprint}")
        dtp, dfp = self._counts(f"det:{detector}")
        w = min(1.0, (ftp + ffp) / 5)
        return w * (ftp + 1) / (ftp + ffp + 2) + (1 - w) * (dtp + 1) / (dtp + dfp + 2)

    def confidence_factor(self, fingerprint: str, detector: str) -> float:
        return 0.6 + 0.8 * self.precision(fingerprint, detector)

    def save(self) -> None:  # compatibility: writes are already durable
        pass

    # ------------------------------------------------------------------ notes & summary
    def note(self, at: float, topic: str, text: str) -> None:
        with self._lock:
            self._db.execute("INSERT INTO notes VALUES (?,?,?)", (at, topic, text))
            self._db.commit()

    def notes(self, topic: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        q = "SELECT * FROM notes" + (" WHERE topic = ?" if topic else "") + " ORDER BY at DESC LIMIT ?"
        with self._lock:
            return [dict(r) for r in self._db.execute(q, ((topic, limit) if topic else (limit,))).fetchall()]

    def has_note(self, topic: str, since: float) -> bool:
        with self._lock:
            return self._db.execute("SELECT 1 FROM notes WHERE topic=? AND at >= ? LIMIT 1",
                                    (topic, since)).fetchone() is not None

    def summary(self) -> dict[str, Any]:
        with self._lock:
            n = self._db.execute("SELECT COUNT(*), COUNT(DISTINCT incident_id), COUNT(DISTINCT run_id) "
                                 "FROM episodes").fetchone()
            by = self._db.execute("SELECT outcome, COUNT(*) c FROM episodes GROUP BY outcome").fetchall()
            sig = self._db.execute("SELECT signal, COUNT(*) c FROM episodes GROUP BY signal ORDER BY c DESC "
                                   "LIMIT 10").fetchall()
            det = self._db.execute("SELECT key, tp, fp FROM detector_outcomes WHERE scope='detector'").fetchall()
        return {"path": self.path, "episodes": n[0], "incidents": n[1], "runs": n[2],
                "outcomes": {r["outcome"]: r["c"] for r in by}, "top_signals": {r["signal"]: r["c"] for r in sig},
                "detectors": {r["key"][4:]: {"tp": r["tp"], "fp": r["fp"]} for r in det}}

    def snapshot(self) -> dict[str, Any]:
        return self.summary()
