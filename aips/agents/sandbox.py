"""Hybrid sandbox for AI agent commands.

Every command an agent wants to run is first judged by the :class:`AgentGuard` (and the learned risk model).
Blocked commands never run. Everything else runs in a **jail**: a throw-away copy of the workspace, never the
real one. The agent's changes reach the real workspace only through :meth:`HybridSandbox.promote`, which
checkpoints every file first, so the guard can still revert them.

Two tiers:

* **local** - on this machine. The process gets a stripped environment (no tokens, keys or cloud credentials
  from the parent), its own TEMP/HOME inside the jail, a wall-clock timeout, an output cap and, by default, a
  dead proxy for well-behaved network clients. On Windows it runs at **low integrity** (it cannot write to the
  user's files outside the jail) inside a **Job Object** (memory cap, process cap, everything killed on exit).
  On Linux/macOS it gets ``setrlimit`` caps and its own session, and ``unshare -rn`` (no network) where the
  kernel allows unprivileged namespaces.
* **remote** - on a sandbox node of the AIPS web (another machine or a cloud VM in the same trust domain).
  Risky but approved work - flagged calls, network or install commands, or a high learned-risk score - goes
  there when one is available, so a mistake lands on a disposable machine instead of this one.

``SandboxResult.isolation`` lists exactly which protections were active for that run, so nothing is overstated.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .guard import AgentGuard, ToolCall, Verdict

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".aips-agent", ".aips-web", ".mypy_cache",
              ".pytest_cache", ".ruff_cache"}
_KEEP_ENV_WIN = ("SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "PROCESSOR_ARCHITECTURE",
                 "NUMBER_OF_PROCESSORS", "OS")
_KEEP_ENV_POSIX = ("LANG", "LC_ALL", "TERM")
_NETWORKY = ("curl", "wget", "pip install", "npm install", "git clone", "git fetch", "git pull", "invoke-webrequest",
             "iwr", "ssh ", "scp ", "nc ", "ncat", "apt", "brew ", "choco ")


@dataclass
class SandboxLimits:
    timeout_s: float = 60.0
    memory_mb: int = 512
    max_processes: int = 32
    max_output_bytes: int = 1_000_000
    max_copy_bytes: int = 200 * 1024 * 1024
    network: bool = False
    low_integrity: bool = True


@dataclass
class SandboxResult:
    job_id: str
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_s: float
    isolation: list[str]
    changed: dict[str, str] = field(default_factory=dict)      # relpath -> "created" | "modified" | "deleted"
    tier: str = "local"
    node: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.error

    def to_dict(self) -> dict[str, Any]:
        return dict(vars(self))

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SandboxResult":
        return cls(**{k: d.get(k) for k in cls.__dataclass_fields__ if k in d})


# --------------------------------------------------------------------------------------------- helpers
def _snapshot(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for f in filenames:
            p = Path(dirpath) / f
            try:
                out[p.relative_to(root).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
            except OSError:
                continue
    return out


def _copy_tree(src: Path, dst: Path, budget: int) -> int:
    used = 0
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        rel = Path(dirpath).relative_to(src)
        (dst / rel).mkdir(parents=True, exist_ok=True)
        for f in filenames:
            s = Path(dirpath) / f
            try:
                size = s.stat().st_size
            except OSError:
                continue
            used += size
            if used > budget:
                raise ValueError(f"workspace is larger than the sandbox copy budget ({budget // (1024 * 1024)} MB)")
            shutil.copy2(s, dst / rel / f)
    return used


def _clean_env(jail: Path, network: bool) -> dict[str, str]:
    keep = _KEEP_ENV_WIN if os.name == "nt" else _KEEP_ENV_POSIX
    env = {k: os.environ[k] for k in keep if k in os.environ}
    path = [str(Path(sys.executable).parent)]
    if os.name == "nt":
        root = os.environ.get("SYSTEMROOT", r"C:\Windows")
        path += [os.path.join(root, "System32"), root, os.path.join(root, "System32", "WindowsPowerShell", "v1.0")]
    else:
        path += ["/usr/local/bin", "/usr/bin", "/bin"]
    path += [p for p in os.environ.get("PATH", "").split(os.pathsep) if "git" in p.lower()]
    env["PATH"] = os.pathsep.join(dict.fromkeys(path))
    tmp, home = jail / "tmp", jail / "home"
    tmp.mkdir(exist_ok=True)
    home.mkdir(exist_ok=True)
    env.update({"TEMP": str(tmp), "TMP": str(tmp), "TMPDIR": str(tmp), "HOME": str(home),
                "USERPROFILE": str(home), "APPDATA": str(home), "LOCALAPPDATA": str(home),
                "AIPS_SANDBOX": "1", "PYTHONDONTWRITEBYTECODE": "1"})
    if not network:
        dead = "http://127.0.0.1:9"
        env.update({"HTTP_PROXY": dead, "HTTPS_PROXY": dead, "ALL_PROXY": dead, "http_proxy": dead,
                    "https_proxy": dead, "all_proxy": dead, "NO_PROXY": "", "PIP_NO_INDEX": "1"})
    return env


# --------------------------------------------------------------------------------------------- Windows
class _Win:
    """Low-integrity process inside a Job Object, using only ctypes."""

    JobObjectExtendedLimitInformation = 9
    LIMIT_ACTIVE_PROCESS = 0x8
    LIMIT_JOB_MEMORY = 0x200
    LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x400

    def __init__(self) -> None:
        from ctypes import wintypes as w
        self.w = w
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.adv = ctypes.WinDLL("advapi32", use_last_error=True)

        class IO(ctypes.Structure):
            _fields_ = [(n, ctypes.c_ulonglong) for n in ("r", "w", "o", "rb", "wb", "ob")]

        class BASIC(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                        ("LimitFlags", w.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", w.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", w.DWORD), ("SchedulingClass", w.DWORD)]

        class EXT(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BASIC), ("IoInfo", IO), ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        class SI(ctypes.Structure):
            _fields_ = [("cb", w.DWORD), ("lpReserved", w.LPWSTR), ("lpDesktop", w.LPWSTR), ("lpTitle", w.LPWSTR),
                        ("dwX", w.DWORD), ("dwY", w.DWORD), ("dwXSize", w.DWORD), ("dwYSize", w.DWORD),
                        ("dwXCountChars", w.DWORD), ("dwYCountChars", w.DWORD), ("dwFillAttribute", w.DWORD),
                        ("dwFlags", w.DWORD), ("wShowWindow", w.WORD), ("cbReserved2", w.WORD),
                        ("lpReserved2", ctypes.c_void_p), ("hStdInput", w.HANDLE), ("hStdOutput", w.HANDLE),
                        ("hStdError", w.HANDLE)]

        class PI(ctypes.Structure):
            _fields_ = [("hProcess", w.HANDLE), ("hThread", w.HANDLE), ("dwProcessId", w.DWORD),
                        ("dwThreadId", w.DWORD)]

        class SA(ctypes.Structure):
            _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", w.DWORD)]

        class TML(ctypes.Structure):
            _fields_ = [("Label", SA)]

        self.EXT, self.SI, self.PI, self.TML = EXT, SI, PI, TML
        k, a = self.k32, self.adv
        k.CreateJobObjectW.restype = w.HANDLE
        k.CreateJobObjectW.argtypes = [ctypes.c_void_p, w.LPCWSTR]
        k.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
        k.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        k.TerminateJobObject.argtypes = [w.HANDLE, ctypes.c_uint]
        k.ResumeThread.argtypes = [w.HANDLE]
        k.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
        k.WaitForSingleObject.restype = w.DWORD
        k.GetExitCodeProcess.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
        k.CloseHandle.argtypes = [w.HANDLE]
        k.GetCurrentProcess.restype = w.HANDLE
        k.LocalFree.argtypes = [ctypes.c_void_p]
        a.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
        a.DuplicateTokenEx.argtypes = [w.HANDLE, w.DWORD, ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                                       ctypes.POINTER(w.HANDLE)]
        a.ConvertStringSidToSidW.argtypes = [w.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
        a.GetLengthSid.argtypes = [ctypes.c_void_p]
        a.GetLengthSid.restype = w.DWORD
        a.SetTokenInformation.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
        a.CreateProcessAsUserW.argtypes = [w.HANDLE, w.LPCWSTR, w.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, w.BOOL,
                                           w.DWORD, ctypes.c_void_p, w.LPCWSTR, ctypes.POINTER(SI),
                                           ctypes.POINTER(PI)]

    def _err(self, what: str) -> OSError:
        code = ctypes.get_last_error()
        return OSError(code, f"{what} failed: {ctypes.FormatError(code).strip()}")

    def low_token(self) -> Any:
        w, k, a = self.w, self.k32, self.adv
        tok, dup = w.HANDLE(), w.HANDLE()
        # TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT
        if not a.OpenProcessToken(k.GetCurrentProcess(), 0x2 | 0x8 | 0x1 | 0x80, ctypes.byref(tok)):
            raise self._err("OpenProcessToken")
        try:
            # MAXIMUM_ALLOWED, SecurityImpersonation=2, TokenPrimary=1
            if not a.DuplicateTokenEx(tok, 0x02000000, None, 2, 1, ctypes.byref(dup)):
                raise self._err("DuplicateTokenEx")
        finally:
            k.CloseHandle(tok)
        sid = ctypes.c_void_p()
        if not a.ConvertStringSidToSidW("S-1-16-4096", ctypes.byref(sid)):         # Low Mandatory Level
            raise self._err("ConvertStringSidToSid")
        try:
            tml = self.TML()
            tml.Label.Sid, tml.Label.Attributes = sid, 0x20                           # SE_GROUP_INTEGRITY
            if not a.SetTokenInformation(dup, 25, ctypes.byref(tml),                  # TokenIntegrityLevel
                                         ctypes.sizeof(tml) + a.GetLengthSid(sid)):
                raise self._err("SetTokenInformation")
        finally:
            k.LocalFree(sid)
        return dup

    def job(self, limits: SandboxLimits) -> Any:
        h = self.k32.CreateJobObjectW(None, None)
        if not h:
            raise self._err("CreateJobObject")
        info = self.EXT()
        info.BasicLimitInformation.LimitFlags = (self.LIMIT_ACTIVE_PROCESS | self.LIMIT_JOB_MEMORY |
                                                 self.LIMIT_KILL_ON_JOB_CLOSE | self.LIMIT_DIE_ON_UNHANDLED_EXCEPTION)
        info.BasicLimitInformation.ActiveProcessLimit = limits.max_processes
        info.JobMemoryLimit = limits.memory_mb * 1024 * 1024
        if not self.k32.SetInformationJobObject(h, self.JobObjectExtendedLimitInformation, ctypes.byref(info),
                                                ctypes.sizeof(info)):
            raise self._err("SetInformationJobObject")
        return h

    def run(self, cmdline: str, cwd: Path, env: dict[str, str], limits: SandboxLimits,
            out_path: Path, err_path: Path) -> tuple[int | None, bool, list[str]]:
        import msvcrt
        w, k = self.w, self.k32
        iso: list[str] = []
        token = None
        if limits.low_integrity:
            subprocess.run(["icacls", str(cwd), "/setintegritylevel", "(OI)(CI)low", "/T", "/Q"],
                           capture_output=True, check=False)
            token = self.low_token()
            iso.append("windows-low-integrity")
        job = self.job(limits)
        iso.append(f"job-object(memory {limits.memory_mb} MB, {limits.max_processes} processes, kill-on-close)")
        block = ("\0".join(f"{a}={b}" for a, b in sorted(env.items(), key=lambda x: x[0].upper())) + "\0\0")
        env_buf = ctypes.create_unicode_buffer(block, len(block))
        with open(out_path, "wb") as out, open(err_path, "wb") as err, open(os.devnull, "rb") as nul:
            handles = [msvcrt.get_osfhandle(f.fileno()) for f in (nul, out, err)]
            for hdl in handles:
                os.set_handle_inheritable(hdl, True)
            si = self.SI()
            si.cb = ctypes.sizeof(si)
            si.dwFlags = 0x100                                                        # STARTF_USESTDHANDLES
            si.hStdInput, si.hStdOutput, si.hStdError = handles
            pi = self.PI()
            flags = 0x4 | 0x400 | 0x08000000 | 0x01000000   # SUSPENDED|UNICODE_ENV|NO_WINDOW|BREAKAWAY_FROM_JOB
            buf = ctypes.create_unicode_buffer(cmdline)
            if token is not None:
                ok = self.adv.CreateProcessAsUserW(token, None, buf, None, None, True, flags, env_buf, str(cwd),
                                                   ctypes.byref(si), ctypes.byref(pi))
                if not ok and ctypes.get_last_error() == 5:                          # breakaway not permitted
                    ok = self.adv.CreateProcessAsUserW(token, None, buf, None, None, True, flags & ~0x01000000,
                                                       env_buf, str(cwd), ctypes.byref(si), ctypes.byref(pi))
            else:
                k.CreateProcessW.argtypes = self.adv.CreateProcessAsUserW.argtypes[1:]
                ok = k.CreateProcessW(None, buf, None, None, True, flags & ~0x01000000, env_buf, str(cwd),
                                      ctypes.byref(si), ctypes.byref(pi))
            if not ok:
                e = self._err("CreateProcess")
                k.CloseHandle(job)
                if token is not None:
                    k.CloseHandle(token)
                raise e
            try:
                if not k.AssignProcessToJobObject(job, pi.hProcess):
                    k.TerminateProcess(pi.hProcess, 1)
                    raise self._err("AssignProcessToJobObject")
                k.ResumeThread(pi.hThread)
                rc = k.WaitForSingleObject(pi.hProcess, int(limits.timeout_s * 1000))
                timed_out = rc == 0x102                                              # WAIT_TIMEOUT
                if timed_out:
                    k.TerminateJobObject(job, 1)
                    k.WaitForSingleObject(pi.hProcess, 5000)
                code = w.DWORD()
                k.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
                # everything the command started is killed with it
                k.TerminateJobObject(job, 0)
                return (None if timed_out else int(code.value)), timed_out, iso
            finally:
                for hdl in (pi.hThread, pi.hProcess, job):
                    k.CloseHandle(hdl)
                if token is not None:
                    k.CloseHandle(token)


# --------------------------------------------------------------------------------------------- local tier
class LocalSandbox:
    def __init__(self, root: str | Path | None = None, limits: SandboxLimits | None = None):
        self.root = Path(root) if root else Path(tempfile.gettempdir()) / "aips-sandbox"
        self.root.mkdir(parents=True, exist_ok=True)
        self.limits = limits or SandboxLimits()
        self.jobs: dict[str, Path] = {}

    def prepare(self, workspace: str | Path | None = None, files: dict[str, bytes] | None = None,
                job_id: str | None = None) -> tuple[str, Path]:
        job_id = job_id or uuid.uuid4().hex[:12]
        jail = self.root / job_id
        work = jail / "work"
        work.mkdir(parents=True, exist_ok=False)
        if workspace:
            _copy_tree(Path(workspace), work, self.limits.max_copy_bytes)
        for rel, data in (files or {}).items():
            dest = (work / rel).resolve()
            if not str(dest).startswith(str(work.resolve())):
                raise ValueError(f"file path escapes the jail: {rel}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
        self.jobs[job_id] = jail
        return job_id, work

    def run(self, command: str, workspace: str | Path | None = None, files: dict[str, bytes] | None = None,
            limits: SandboxLimits | None = None, job_id: str | None = None) -> SandboxResult:
        lim = limits or self.limits
        t0 = time.monotonic()
        job_id, work = self.prepare(workspace, files, job_id)
        jail = work.parent
        before = _snapshot(work)
        env = _clean_env(jail, lim.network)
        iso = ["jail-copy (real workspace untouched)", "clean-environment (no inherited secrets)",
               f"timeout {lim.timeout_s:.0f}s"]
        if not lim.network:
            iso.append("network: dead proxy for HTTP clients (best effort)")
        out_p, err_p = jail / "stdout.txt", jail / "stderr.txt"
        code: int | None
        timed_out, error = False, ""
        try:
            if os.name == "nt":
                cmdline = f'"{env.get("COMSPEC", "cmd.exe")}" /d /s /c "{command}"'
                try:
                    code, timed_out, extra = _Win().run(cmdline, work, env, lim, out_p, err_p)
                except OSError as exc:
                    if not lim.low_integrity:
                        raise
                    # fall back to a Job Object without low integrity, and say so
                    lim2 = SandboxLimits(**{**vars(lim), "low_integrity": False})
                    code, timed_out, extra = _Win().run(cmdline, work, env, lim2, out_p, err_p)
                    extra.append(f"low-integrity unavailable ({exc.strerror or exc})")
                iso += extra
            else:
                code, timed_out, extra = _posix_run(command, work, env, lim, out_p, err_p)
                iso += extra
        except Exception as exc:  # noqa: BLE001 - a sandbox failure is a result, not a crash
            code, error = None, f"{type(exc).__name__}: {exc}"
        after = _snapshot(work)
        changed = {p: "created" for p in after.keys() - before.keys()}
        changed.update({p: "deleted" for p in before.keys() - after.keys()})
        changed.update({p: "modified" for p in before.keys() & after.keys() if before[p] != after[p]})
        cap = lim.max_output_bytes

        def read(p: Path) -> str:
            try:
                data = p.read_bytes()
            except OSError:
                return ""
            tail = f"\n[... {len(data) - cap} bytes cut]" if len(data) > cap else ""
            return data[:cap].decode("utf-8", "replace") + tail

        return SandboxResult(job_id, code, read(out_p), read(err_p), timed_out, round(time.monotonic() - t0, 3), iso,
                             dict(sorted(changed.items())), "local", "", error)

    def workdir(self, job_id: str) -> Path:
        return self.jobs[job_id] / "work"

    def cleanup(self, job_id: str) -> None:
        jail = self.jobs.pop(job_id, None)
        if jail and jail.exists():
            if os.name == "nt":
                subprocess.run(["icacls", str(jail), "/reset", "/T", "/Q"], capture_output=True, check=False)
            shutil.rmtree(jail, ignore_errors=True)


def _posix_run(command: str, work: Path, env: dict[str, str], lim: SandboxLimits, out_p: Path,
               err_p: Path) -> tuple[int | None, bool, list[str]]:
    import resource  # noqa: PLC0415 - POSIX only

    if sys.platform == "darwin":
        # macOS accepts RLIMIT_AS but does not enforce it, so no memory cap is claimed there
        iso = ["rlimits(file size 256 MB, CPU time; memory cap NOT enforced on macOS)",
               "own-session (killed as a group)"]
    else:
        iso = [f"rlimits(address space {lim.memory_mb} MB, {lim.max_processes} processes, file size 256 MB)",
               "own-session (killed as a group)"]

    def limit() -> None:
        mem = lim.memory_mb * 1024 * 1024
        for res, val in ((resource.RLIMIT_AS, mem), (resource.RLIMIT_FSIZE, 256 * 1024 * 1024),
                         (resource.RLIMIT_CPU, int(lim.timeout_s) + 5)):
            try:
                resource.setrlimit(res, (val, val))
            except (ValueError, OSError):
                pass
        if hasattr(resource, "RLIMIT_NPROC") and sys.platform.startswith("linux"):
            try:
                resource.setrlimit(resource.RLIMIT_NPROC, (lim.max_processes + 50, lim.max_processes + 50))
            except (ValueError, OSError):
                pass

    argv = ["/bin/sh", "-c", command]
    if not lim.network and shutil.which("unshare"):
        probe = subprocess.run(["unshare", "-rn", "true"], capture_output=True, check=False)
        if probe.returncode == 0:
            argv = ["unshare", "-rn"] + argv
            iso.append("network-namespace (no network)")
    with open(out_p, "wb") as out, open(err_p, "wb") as err:
        p = subprocess.Popen(argv, cwd=work, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                             preexec_fn=limit, start_new_session=True)  # noqa: PLW1509 - limits must apply pre-exec
        try:
            return p.wait(timeout=lim.timeout_s), False, iso
        except subprocess.TimeoutExpired:
            import signal  # noqa: PLC0415
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except OSError:
                p.kill()
            p.wait()
            return None, True, iso


# --------------------------------------------------------------------------------------------- hybrid
@dataclass
class HybridOutcome:
    verdict: str
    risk: float
    reasons: list[str]
    tier: str                         # local | remote | not-run
    result: SandboxResult | None = None
    call_id: str = ""
    learned_risk: float | None = None
    approval_needed: bool = False


class HybridSandbox:
    """Judge, then run in the right tier. ``remote`` sends a job to a sandbox node of the AIPS web."""

    def __init__(self, local: LocalSandbox, guard: AgentGuard | None = None,
                 remote: Callable[[dict[str, Any]], SandboxResult] | None = None, risk_model: Any = None,
                 approver: Callable[[str, str], bool] | None = None, remote_risk: float = 0.5):
        self.local = local
        self.guard = guard or AgentGuard()
        self.remote = remote
        self.risk_model = risk_model
        self.approver = approver
        self.remote_risk = remote_risk

    def choose_tier(self, command: str, verdict: Verdict, learned: float | None) -> str:
        low = command.lower()
        risky = (verdict != Verdict.ALLOW or any(n in low for n in _NETWORKY)
                 or (learned is not None and learned >= self.remote_risk))
        return "remote" if risky and self.remote is not None else "local"

    def run(self, agent_id: str, command: str, workspace: str | Path | None = None, session_id: str | None = None,
            limits: SandboxLimits | None = None) -> HybridOutcome:
        cwd = str(workspace) if workspace else None
        dec = self.guard.check(ToolCall(agent_id, "Bash", {"command": command}, session_id=session_id, cwd=cwd))
        learned = round(self.risk_model.predict("Bash", command), 3) if self.risk_model is not None else None
        out = HybridOutcome(dec.verdict.value, dec.risk, list(dec.reasons), "not-run", None, dec.call_id, learned)
        if dec.verdict == Verdict.BLOCK:
            return out
        if dec.verdict == Verdict.ASK:
            if not (self.approver and self.approver(dec.call_id, command)):
                out.approval_needed = True
                return out
            out.reasons.append("[ask] approved by a human")
        tier = self.choose_tier(command, dec.verdict, learned)
        lim = limits or self.local.limits
        if tier == "remote":
            files = _pack(Path(workspace), lim.max_copy_bytes) if workspace else {}
            res = self.remote({"command": command, "files": files, "limits": vars(lim), "agent": agent_id})
            res.tier = "remote"
        else:
            res = self.local.run(command, workspace, limits=lim)
        out.tier, out.result = tier, res
        self.guard.record_result(dec.call_id, res.ok, (res.stdout or "") + (res.stderr or ""))
        return out

    def promote(self, agent_id: str, job: SandboxResult, workspace: str | Path, session_id: str | None = None,
                files: dict[str, bytes] | None = None) -> dict[str, Any]:
        """Copy a job's changes into the real workspace. Each file goes through the guard, which checkpoints it
        first, so ``guard.revert(agent_id)`` can undo the promotion."""
        ws = Path(workspace)
        applied, refused = [], []
        src_root = self.local.workdir(job.job_id) if job.tier == "local" and job.job_id in self.local.jobs else None
        for rel, kind in job.changed.items():
            target = (ws / rel)
            if kind == "deleted":
                call = ToolCall(agent_id, "Bash", {"command": f'rm "{target}"'}, session_id=session_id, cwd=str(ws))
            else:
                call = ToolCall(agent_id, "Write", {"file_path": str(target), "content": "<sandbox output>"},
                                session_id=session_id, cwd=str(ws))
            dec = self.guard.check(call)
            if not dec.allowed:
                refused.append(f"{rel}: {dec.summary()}")
                continue
            if kind == "deleted":
                if target.exists():
                    target.unlink()
            else:
                data = files[rel] if files and rel in files else (src_root / rel).read_bytes() if src_root else None
                if data is None:
                    refused.append(f"{rel}: no content available to promote")
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            self.guard.record_result(dec.call_id, True)
            applied.append(rel)
        return {"applied": applied, "refused": refused}


def _pack(root: Path, budget: int) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    used = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for f in filenames:
            p = Path(dirpath) / f
            data = p.read_bytes()
            used += len(data)
            if used > budget:
                raise ValueError("workspace is larger than the sandbox copy budget")
            out[p.relative_to(root).as_posix()] = data
    return out
