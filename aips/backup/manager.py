"""Backup manager: snapshot, protect, replicate, retain, verify, restore.

Process (answers "backup frequency, retention, isolation and restoration"):

1. **Snapshot** the main layer into the backup-copy layer every
   ``interval_s`` (incremental: only new content is stored).
2. **Mass-change guard** compares the new snapshot with its parent. If a large
   fraction of files changed *and* the changed content looks encrypted (high
   Shannon entropy or ransomware-style extensions) the snapshot is flagged
   ``suspect``, replication is held and a CRITICAL ``mass_encryption``
   finding is raised. Suspect snapshots are never copied to the vault and
   never chosen as "latest clean".
3. **Replicate** clean snapshots to the vault through its network gate.
4. **Retention** (grandfather-father-son) prunes the copy layer; the vault
   keeps its own retention lock.
5. **Scrub / restore drills** periodically prove that backups are restorable,
   not merely present.
"""

from __future__ import annotations

import math
import os
import shutil
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..core.models import Category, Evidence, Finding, Severity, new_id
from .store import FileEntry, IntegrityError, Manifest, ObjectStore, sha256_file
from .vault import Vault

RANSOM_EXTENSIONS = (".locked", ".encrypted", ".crypt", ".enc", ".crypted", ".ransom", ".lockbit", ".wncry")


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


@dataclass
class MassChangeReport:
    suspicious: bool
    changed: int
    total: int
    change_ratio: float
    mean_entropy: float
    ransom_extensions: int
    reasons: list[str] = field(default_factory=list)


@dataclass
class BackupPolicy:
    interval_s: float = 3600
    keep_last: int = 24
    keep_daily: int = 7
    keep_weekly: int = 4
    keep_monthly: int = 6
    change_ratio_threshold: float = 0.3
    entropy_threshold: float = 7.2
    min_files_for_guard: int = 5
    drill_interval_s: float = 7 * 86400


@dataclass
class RestoreReport:
    snapshot_id: str
    files: int
    bytes: int
    verified: bool
    target: str
    errors: list[str] = field(default_factory=list)


class BackupManager:
    def __init__(self, main_root: str | os.PathLike, copy_store: ObjectStore, hmac_key: bytes,
                 vault: Vault | None = None, policy: BackupPolicy | None = None,
                 replication_ip: str | None = None, exclude: tuple[str, ...] = ()):
        self.main_root = Path(main_root)
        self.copy = copy_store
        self.hmac_key = hmac_key
        self.vault = vault
        self.policy = policy or BackupPolicy()
        self.replication_ip = replication_ip
        self.exclude = exclude
        self.replication_held = False
        self.hold_reason = ""
        self.last_snapshot_at: float | None = None
        self.last_drill: dict | None = None
        self.pending_findings: list[Finding] = []

    # -- layer 1 -> layer 2 ---------------------------------------------------
    def _walk(self) -> dict[str, Path]:
        out = {}
        for p in sorted(self.main_root.rglob("*")):
            if p.is_file() and not p.is_symlink():
                rel = p.relative_to(self.main_root).as_posix()
                if not any(rel.startswith(e) for e in self.exclude):
                    out[rel] = p
        return out

    def latest(self, clean_only: bool = True) -> Manifest | None:
        ms = [m for m in self.copy.manifests() if m.verify(self.hmac_key) and (not clean_only or not m.suspect)]
        return ms[-1] if ms else None

    def snapshot(self, now: float | None = None, source: str = "main") -> Manifest:
        now = time.time() if now is None else now
        parent = self.latest(clean_only=True)
        files: dict[str, FileEntry] = {}
        changed_samples: list[bytes] = []
        for rel, p in self._walk().items():
            st = p.stat()
            prev = parent.files.get(rel) if parent else None
            if prev and prev.size == st.st_size and prev.mtime == st.st_mtime and self.copy.has(prev.sha256):
                files[rel] = prev
                continue
            data = p.read_bytes()
            digest = self.copy.put(data)
            files[rel] = FileEntry(digest, st.st_size, st.st_mode & 0o7777, st.st_mtime)
            if prev is None or prev.sha256 != digest:
                changed_samples.append(data[:4096])
        sid = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + new_id("S")[2:]
        m = Manifest(sid, now, source, files, parent.id if parent else None)
        report = self.inspect_changes(parent, m, changed_samples)
        if report.suspicious:
            m.suspect = True
            m.notes.extend(report.reasons)
            self.hold_replication("mass-change guard: " + "; ".join(report.reasons))
            self.pending_findings.append(Finding(
                detector="backup.guard", category=Category.DATA_INTEGRITY, severity=Severity.CRITICAL,
                confidence=0.9, asset_id=str(self._asset_id()), signal="mass_encryption",
                title=f"Possible ransomware: {report.changed}/{report.total} files modified or removed, "
                      f"mean entropy {report.mean_entropy:.2f} bits/byte",
                description="; ".join(report.reasons), created_at=now,
                evidence=[Evidence("file_change", "backup.guard", {
                    "snapshot": sid, "changed": report.changed, "total": report.total,
                    "change_ratio": round(report.change_ratio, 3), "mean_entropy": round(report.mean_entropy, 3),
                    "ransom_extensions": report.ransom_extensions}, now)]))
        m.sign(self.hmac_key)
        self.copy.save_manifest(m)
        self.last_snapshot_at = now
        return m

    asset_id: str | None = None

    def _asset_id(self) -> str:
        return self.asset_id or self.main_root.name

    def inspect_changes(self, parent: Manifest | None, m: Manifest, samples: list[bytes]) -> MassChangeReport:
        pol = self.policy
        total = max(len(m.files), 1)
        if parent is None:
            return MassChangeReport(False, len(m.files), total, 1.0, 0.0, 0)
        modified = [k for k, v in m.files.items() if k in parent.files and parent.files[k].sha256 != v.sha256]
        added = [k for k in m.files if k not in parent.files]
        removed = [k for k in parent.files if k not in m.files]
        n_changed = len(modified) + len(removed)          # original files that no longer exist unchanged
        base = max(len(parent.files), 1)
        total = base
        ratio = n_changed / base
        ent = (sum(shannon_entropy(s) for s in samples) / len(samples)) if samples else 0.0
        ransom_ext = sum(1 for k in added + modified if k.lower().endswith(RANSOM_EXTENSIONS))
        reasons = []
        suspicious = False
        if len(parent.files) >= pol.min_files_for_guard and ratio >= pol.change_ratio_threshold:
            if ent >= pol.entropy_threshold:
                suspicious = True
                reasons.append(f"{ratio:.0%} of files changed with high-entropy content ({ent:.2f} bits/byte)")
            if ransom_ext >= max(2, int(0.1 * base)):
                suspicious = True
                reasons.append(f"{ransom_ext} files renamed with ransomware-style extensions")
        return MassChangeReport(suspicious, n_changed, total, ratio, ent, ransom_ext, reasons)

    # -- layer 2 -> vault -----------------------------------------------------
    def hold_replication(self, reason: str) -> None:
        self.replication_held, self.hold_reason = True, reason

    def resume_replication(self) -> None:
        self.replication_held, self.hold_reason = False, ""

    def replicate(self, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        if self.vault is None:
            return {"replicated": 0, "reason": "no vault configured"}
        if self.replication_held:
            return {"replicated": 0, "reason": f"held: {self.hold_reason}"}
        done, objects = 0, 0
        vault_ids = {m.id for m in self.vault.snapshots(self.replication_ip)}
        for m in self.copy.manifests():
            if m.id in vault_ids or m.suspect or not m.verify(self.hmac_key):
                continue
            objects += self.vault.receive(m, self.copy, self.replication_ip, now)
            done += 1
        return {"replicated": done, "objects": objects}

    # -- retention ------------------------------------------------------------
    def retention_plan(self) -> tuple[list[str], list[str]]:
        """Return (keep, delete) snapshot ids under the GFS policy. Suspect snapshots are kept for forensics."""
        pol = self.policy
        ms = self.copy.manifests()
        keep: set[str] = {m.id for m in ms if m.suspect}
        clean = [m for m in ms if not m.suspect]
        keep |= {m.id for m in clean[-pol.keep_last:]}

        def bucket(fmt: str, limit: int) -> None:
            seen: list[str] = []
            for m in reversed(clean):
                b = datetime.fromtimestamp(m.created_at, tz=timezone.utc).strftime(fmt)
                if b not in seen:
                    seen.append(b)
                    keep.add(m.id)
                if len(seen) >= limit:
                    break

        bucket("%Y-%m-%d", pol.keep_daily)
        bucket("%G-W%V", pol.keep_weekly)
        bucket("%Y-%m", pol.keep_monthly)
        delete = [m.id for m in ms if m.id not in keep]
        return sorted(keep), delete

    def prune(self) -> list[str]:
        _, delete = self.retention_plan()
        for sid in delete:
            self.copy.delete_manifest(sid)
        referenced = {e.sha256 for m in self.copy.manifests() for e in m.files.values()}
        for d in list(self.copy.digests()):
            if d not in referenced:
                self.copy.delete_object(d)
        return delete

    # -- restore --------------------------------------------------------------
    def _resolve(self, snapshot: str) -> Manifest:
        if snapshot in ("latest", "latest_clean"):
            m = self.latest(clean_only=True)
            if m is None:
                raise IntegrityError("no clean snapshot available")
            return m
        m = self.copy.load_manifest(snapshot)
        if not m.verify(self.hmac_key):
            raise IntegrityError(f"manifest {snapshot} signature invalid")
        return m

    def restore(self, snapshot: str, target: str | os.PathLike | None = None, from_vault: bool = False,
                source_ip: str | None = None, clean_target: bool = False) -> RestoreReport:
        m = self._resolve(snapshot) if not from_vault else self._vault_manifest(snapshot, source_ip)
        root = Path(target) if target else self.main_root
        root.mkdir(parents=True, exist_ok=True)
        root_resolved = root.resolve()
        errors: list[str] = []
        if clean_target:
            for rel, p in self._walk_root(root).items():
                if rel not in m.files:
                    p.unlink()
        n, total = 0, 0
        for rel, entry in m.files.items():
            dest = (root / rel).resolve()
            if root_resolved not in dest.parents and dest != root_resolved:
                errors.append(f"refused path outside target: {rel}")
                continue
            try:
                data = (self.vault.fetch(entry.sha256, source_ip) if from_vault and self.vault
                        else self.copy.get(entry.sha256))
            except IntegrityError as exc:
                errors.append(str(exc))
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp = dest.with_name(dest.name + ".aips-restore")
            tmp.write_bytes(data)
            os.replace(tmp, dest)
            try:
                os.chmod(dest, entry.mode or 0o644)
                os.utime(dest, (entry.mtime, entry.mtime))
            except OSError:
                pass
            n += 1
            total += len(data)
        verified = not errors and all(sha256_file(root / rel) == e.sha256 for rel, e in m.files.items())
        return RestoreReport(m.id, n, total, verified, str(root), errors)

    @staticmethod
    def _walk_root(root: Path) -> dict[str, Path]:
        return {p.relative_to(root).as_posix(): p for p in root.rglob("*") if p.is_file()}

    def _vault_manifest(self, snapshot: str, source_ip: str | None) -> Manifest:
        if not self.vault:
            raise IntegrityError("no vault configured")
        ms = self.vault.snapshots(source_ip)
        if snapshot in ("latest", "latest_clean"):
            ms = [m for m in ms if not m.suspect]
            if not ms:
                raise IntegrityError("vault holds no clean snapshot")
            return ms[-1]
        for m in ms:
            if m.id == snapshot:
                return m
        raise IntegrityError(f"snapshot {snapshot} not in vault")

    def restore_drill(self, now: float | None = None) -> dict:
        """Restore the latest clean snapshot into a scratch directory and verify it end-to-end."""
        now = time.time() if now is None else now
        tmp = tempfile.mkdtemp(prefix="aips-drill-")
        try:
            rep = self.restore("latest_clean", tmp)
            self.last_drill = {"at": now, "snapshot": rep.snapshot_id, "ok": rep.verified,
                               "files": rep.files, "errors": rep.errors}
        except IntegrityError as exc:
            self.last_drill = {"at": now, "snapshot": None, "ok": False, "files": 0, "errors": [str(exc)]}
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        return self.last_drill

    def verify(self) -> dict:
        bad = []
        for m in self.copy.manifests():
            if not m.verify(self.hmac_key):
                bad.append(m.id)
        corrupt = 0
        for d in self.copy.digests():
            try:
                self.copy.get(d)
            except IntegrityError:
                corrupt += 1
        out = {"copy_manifests_bad": bad, "copy_objects_corrupt": corrupt}
        if self.vault:
            out["vault"] = self.vault.scrub()
        return out

    def due(self, now: float) -> bool:
        return self.last_snapshot_at is None or now - self.last_snapshot_at >= self.policy.interval_s

    def drain_findings(self) -> list[Finding]:
        out, self.pending_findings = self.pending_findings, []
        return out

    def status(self) -> dict:
        ms = self.copy.manifests()
        return {"snapshots": len(ms), "suspect": sum(1 for m in ms if m.suspect),
                "latest_clean": (self.latest().id if self.latest() else None),
                "replication_held": self.replication_held, "hold_reason": self.hold_reason,
                "last_drill": self.last_drill}
