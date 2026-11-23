"""AgentGuard: AIPS protection for AI agents.

An AI agent (a coding assistant, an autonomous ops bot, an LLM with tools) acts on infrastructure through
*tool calls*: run a shell command, write a file, call an API. AgentGuard sits in front of those calls and
applies the same principles AIPS applies to infrastructure and identities:

* **Detect** - every call is judged *before* it runs: built-in harm rules (destroying data, running code from
  the internet, reaching for secrets, weakening security controls, gaining privilege, attacking the guard
  itself), the agent's policy (allowed / denied / ask-first tools, workspace scope, approved domains), and its
  *behaviour* (the same call in a loop, bursts, error storms, budget). Risk is a noisy-OR of indicators.
* **Decide** - ALLOW, FLAG (allow and report), ASK (a human must approve) or BLOCK. Untrusted content that
  tries to give the agent new instructions (prompt injection) *taints* the session: from then on, risky calls
  need a human.
* **Freeze** - repeated or critical blocks freeze the agent: every further call is refused until a human
  unfreezes it. Inside AIPS the freeze is a Level 3 decision taken through the authorisation policy.
* **Save** - before a call that may change or delete files runs, the affected files are checkpointed
  (content-addressed, verified on restore).
* **Fix** - ``revert`` restores every file the agent changed from its first suspicious call onward, runs any
  registered undo callbacks, and lists what cannot be undone automatically for a human. A revert can itself
  be undone.

It works embedded in AIPS (findings flow into the three-level hierarchy), in-process around Python tools
(``guarded``), as a Claude Code hook (``claude_code.py``) and over the AIPS HTTP API.
"""

from __future__ import annotations

import fnmatch
import glob as globmod
import hashlib
import json
import os
import re
import shlex
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from ..core.clock import Clock, SystemClock
from ..core.models import Category, Evidence, Finding, Severity
from .rules import DEFAULT_RULES, HarmRule, injection_hits, is_egress, match_rules, secret_hits
from .store import AgentStore, CallRow

SHELL_TOOLS = {"bash", "shell", "sh", "zsh", "powershell", "pwsh", "cmd", "terminal", "run_command", "run_shell",
               "exec", "execute", "execute_command", "run_in_terminal", "computer.run", "subprocess"}
WRITE_TOOLS = {"write", "edit", "multiedit", "notebookedit", "write_file", "edit_file", "create_file", "save_file",
               "str_replace_editor", "str_replace_based_edit_tool", "apply_patch", "replace", "append_file"}
DELETE_TOOLS = {"delete", "delete_file", "remove", "remove_file", "rm", "unlink", "move_file", "rename"}
READ_TOOLS = {"read", "read_file", "glob", "grep", "ls", "list_dir", "list_directory", "view", "cat", "search",
              "find", "open_file"}
NET_TOOLS = {"webfetch", "web_fetch", "fetch", "http", "http_request", "request", "browser", "navigate", "curl",
             "websearch", "web_search", "send_email", "send_message", "post", "upload", "webhook"}
PATH_KEYS = ("file_path", "path", "notebook_path", "filename", "file", "target", "destination", "dest", "source",
             "src", "directory", "dir")
URL_KEYS = ("url", "uri", "endpoint", "href")
SHELL_KEYS = ("command", "cmd", "script", "code", "commands")
_URL = re.compile(r"https?://[^\s'\"<>|)]+", re.IGNORECASE)
_MUTATING_VERBS = re.compile(
    r"(?:^|[;&|(]\s*|\s)(rm|del|erase|rd|rmdir|remove-item|ri|mv|move|move-item|ren|rename|rename-item|truncate|shred|"
    r"unlink|cp|copy|copy-item|tee|set-content|sc|out-file|add-content|clear-content|sed\s+-i|perl\s+-pi)\b([^;&|\n]*)",
    re.IGNORECASE)
_REDIRECT = re.compile(r"(?<![0-9&])>>?\s*['\"]?([^\s'\";&|]+)")
_DESTRUCTIVE_GROUPS = {"destructive", "tampering", "self_protection"}


class Verdict(str, Enum):
    ALLOW = "allow"
    FLAG = "flag"          # allowed, reported
    ASK = "ask"            # needs a human
    BLOCK = "block"


@dataclass
class ToolCall:
    agent_id: str
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    session_id: str | None = None
    cwd: str | None = None
    ts: float | None = None
    call_id: str | None = None


@dataclass
class AgentPolicy:
    allow_tools: list[str] = field(default_factory=lambda: ["*"])
    deny_tools: list[str] = field(default_factory=list)
    ask_tools: list[str] = field(default_factory=list)
    workspace_roots: list[str] = field(default_factory=list)    # empty: the call's cwd, if known
    allow_domains: list[str] = field(default_factory=list)      # empty: any domain
    max_calls_per_min: int = 60
    max_calls_per_session: int = 3000

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AgentPolicy":
        p = cls()
        for k in ("allow_tools", "deny_tools", "ask_tools", "workspace_roots", "allow_domains"):
            if k in d:
                setattr(p, k, [str(x) for x in d[k]])
        for k in ("max_calls_per_min", "max_calls_per_session"):
            if k in d:
                setattr(p, k, int(d[k]))
        return p


@dataclass
class AgentConfig:
    flag_risk: float = 0.3
    ask_risk: float = 0.55
    block_risk: float = 0.8
    loop_window_s: float = 120.0
    loop_flag: int = 5                  # identical calls within the window
    loop_block: int = 10
    error_streak: int = 5
    freeze_after_blocks: int = 3
    freeze_window_s: float = 600.0
    autonomous_freeze: bool = True      # False inside AIPS: Level 3 decides the freeze through the policy
    checkpoint_max_bytes: int = 20 * 1024 * 1024
    checkpoint_max_files: int = 2000
    exfil_window_s: float = 900.0
    disabled_rules: list[str] = field(default_factory=list)
    extra_rules: list[HarmRule] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AgentConfig":
        c = cls()
        for k, v in d.items():
            if k == "extra_rules":
                c.extra_rules = [HarmRule(r["id"], r.get("group", "custom"), r["pattern"], float(r.get("weight", 0.5)),
                                          bool(r.get("critical", False)), r.get("description", "")) for r in v]
            elif hasattr(c, k):
                cur = getattr(c, k)
                setattr(c, k, type(cur)(v) if not isinstance(cur, list) else list(v))
        return c


@dataclass
class AgentDecision:
    call_id: str
    agent_id: str
    verdict: Verdict
    risk: float
    reasons: list[str]
    intent: str
    checkpoints: int = 0
    frozen_now: bool = False
    finding: Finding | None = None

    @property
    def allowed(self) -> bool:
        return self.verdict in (Verdict.ALLOW, Verdict.FLAG)

    def summary(self) -> str:
        why = "; ".join(self.reasons[:4]) or "no risk indicators"
        return f"AIPS {self.verdict.value.upper()} (risk {self.risk:.2f}): {why}"


@dataclass
class RevertReport:
    id: str
    agent_id: str
    calls: list[str]
    restored: list[str]
    removed: list[str]
    undo_callbacks: int
    needs_review: list[str]
    failed: list[str]

    @property
    def ok(self) -> bool:
        return not self.failed


class ActionBlocked(PermissionError):
    def __init__(self, decision: AgentDecision):
        super().__init__(decision.summary())
        self.decision = decision


@dataclass
class _Parsed:
    intent: str                 # shell | write | delete | read | network | mutate | other
    text: str                   # text the harm rules run over
    full_text: str              # every string in the call (secret scanning)
    paths: list[Path]           # files the call reads or changes
    write_paths: list[Path]     # files the call may create / change / delete
    create_ok: list[Path]       # write targets that may not exist yet (revert removes them)
    urls: list[str]


def _strings(x: Any, out: list[str], budget: list[int]) -> None:
    if budget[0] <= 0:
        return
    if isinstance(x, str):
        out.append(x[:budget[0]])
        budget[0] -= len(x)
    elif isinstance(x, dict):
        for v in x.values():
            _strings(v, out, budget)
    elif isinstance(x, (list, tuple)):
        for v in x:
            _strings(v, out, budget)


def _base_tool(tool: str) -> str:
    t = tool.lower()
    if t.startswith("mcp__"):
        t = t.split("__")[-1]
    return t


def _split(cmd: str) -> list[str]:
    try:
        return shlex.split(cmd, posix=os.name != "nt")
    except ValueError:
        return cmd.split()


class AgentGuard:
    name = "agent.guard"

    def __init__(self, config: AgentConfig | None = None, policy: AgentPolicy | None = None,
                 store: AgentStore | None = None, clock: Clock | None = None,
                 policies: dict[str, AgentPolicy] | None = None,
                 on_finding: Callable[[Finding], None] | None = None, audit: Any = None):
        self.config = config or AgentConfig()
        self.policy = policy or AgentPolicy()
        self.policies = dict(policies or {})            # per-agent overrides (glob on agent id)
        self.store = store or AgentStore(":memory:")
        self.clock = clock or SystemClock()
        self.on_finding = on_finding
        self.audit = audit
        disabled = set(self.config.disabled_rules)
        self.rules = [r for r in DEFAULT_RULES if r.id not in disabled] + list(self.config.extra_rules)
        self._undo: dict[str, tuple[Callable[..., Any], dict[str, Any], Any]] = {}

    # ----------------------------------------------------------------------------------------- policy
    def policy_for(self, agent_id: str) -> AgentPolicy:
        for pattern, p in self.policies.items():
            if fnmatch.fnmatch(agent_id, pattern):
                return p
        return self.policy

    def is_frozen(self, agent_id: str) -> bool:
        return self.store.is_frozen(agent_id)

    # ----------------------------------------------------------------------------------------- parsing
    def _parse(self, call: ToolCall) -> _Parsed:
        tool, args = _base_tool(call.tool), call.args or {}
        cwd = Path(call.cwd) if call.cwd else None
        strings: list[str] = []
        _strings(args, strings, [60_000])
        full = "\n".join(strings)

        def resolve(p: str) -> Path:
            q = Path(os.path.expandvars(os.path.expanduser(p.strip().strip("'\""))))
            if not q.is_absolute() and cwd is not None:
                q = cwd / q
            return q

        shell_text = next((str(args[k]) for k in SHELL_KEYS if isinstance(args.get(k), str)), None)
        if shell_text is None and isinstance(args.get("commands"), list):
            shell_text = "\n".join(map(str, args["commands"]))
        named = [str(args[k]) for k in PATH_KEYS if isinstance(args.get(k), str) and args[k]]
        if isinstance(args.get("paths"), list):
            named += [str(p) for p in args["paths"]]
        if isinstance(args.get("edits"), list):          # multi-file patch formats
            named += [str(e.get("file_path") or e.get("path")) for e in args["edits"]
                      if isinstance(e, dict) and (e.get("file_path") or e.get("path"))]
        urls = [str(args[k]) for k in URL_KEYS if isinstance(args.get(k), str)]
        urls += [u for u in _URL.findall(full) if u not in urls]

        if tool in SHELL_TOOLS or shell_text is not None:
            intent = "shell"
        elif tool in WRITE_TOOLS:
            intent = "write"
        elif tool in DELETE_TOOLS:
            intent = "delete"
        elif tool in NET_TOOLS or (urls and not named):
            intent = "network"
        elif tool in READ_TOOLS:
            intent = "read"
        elif re.search(r"delete|remove|drop|destroy|purge|wipe|revoke", tool):
            intent = "delete"
        elif re.search(r"write|create|update|edit|set|put|insert|send|post|push|upload|deploy|grant|move", tool):
            intent = "mutate"
        elif re.search(r"read|get|list|search|query|describe|show|fetch", tool):
            intent = "read"
        else:
            intent = "other"

        paths = [resolve(p) for p in named]
        write_paths: list[Path] = []
        create_ok: list[Path] = []
        if intent in ("write", "delete", "mutate"):
            write_paths = list(paths)
            if intent in ("write", "mutate"):
                create_ok = list(paths)
        if intent == "shell" and shell_text:
            for m in _MUTATING_VERBS.finditer(shell_text):
                verb = m.group(1).lower()
                toks = [t for t in _split(m.group(2)) if t and not t.startswith("-") and not re.fullmatch(r"/[a-z]", t, re.I)]
                cands = []
                for t in toks:
                    if any(ch in t for ch in "*?["):
                        base = str(resolve(t))
                        cands += [Path(x) for x in globmod.glob(base)[: self.config.checkpoint_max_files]]
                    else:
                        cands.append(resolve(t))
                write_paths += cands
                if verb in ("cp", "copy", "copy-item", "mv", "move", "move-item", "tee", "set-content", "sc",
                            "out-file", "add-content") and cands:
                    create_ok.append(cands[-1])
            for m in _REDIRECT.finditer(shell_text):
                tgt = m.group(1)
                if tgt.lower() not in ("/dev/null", "nul", "$null") and not tgt.startswith("&"):
                    p = resolve(tgt)
                    write_paths.append(p)
                    create_ok.append(p)
            paths += write_paths

        if intent == "shell" and shell_text is not None:
            text = shell_text
        elif intent in ("write", "read", "delete"):
            text = "\n".join(named + urls)               # do not judge file *content* as if it were a command
        else:
            text = full
        return _Parsed(intent, text, full, _dedupe(paths), _dedupe(write_paths), _dedupe(create_ok), urls)

    # ----------------------------------------------------------------------------------------- decision
    def check(self, call: ToolCall) -> AgentDecision:
        cfg = self.config
        now = call.ts if call.ts is not None else self.clock.now()
        call_id = call.call_id or uuid.uuid4().hex[:16]
        agent = call.agent_id
        parsed = self._parse(call)
        fp = hashlib.sha256(f"{call.tool}|{json.dumps(call.args, sort_keys=True, default=str)}".encode()).hexdigest()[:16]

        if self.store.is_frozen(agent):
            info = self.store.frozen().get(agent, {})
            dec = AgentDecision(call_id, agent, Verdict.BLOCK, 1.0,
                                [f"agent is frozen ({info.get('reason', '')}); a human must unfreeze it"], parsed.intent)
            self._record(call, dec, parsed, fp, now)
            return dec

        pol = self.policy_for(agent)
        ind: list[tuple[float, str, str, bool]] = []      # weight, reason, group, critical
        force_ask: list[str] = []
        base = _base_tool(call.tool)

        if any(fnmatch.fnmatch(call.tool, p) or fnmatch.fnmatch(base, p) for p in pol.deny_tools):
            ind.append((1.0, f"tool {call.tool} is denied by policy", "policy", True))
        elif not any(fnmatch.fnmatch(call.tool, p) or fnmatch.fnmatch(base, p) for p in pol.allow_tools):
            ind.append((0.6, f"tool {call.tool} is not in the agent's allow list", "policy", False))
        if any(fnmatch.fnmatch(call.tool, p) or fnmatch.fnmatch(base, p) for p in pol.ask_tools):
            force_ask.append(f"policy: {call.tool} always needs approval")

        for r in match_rules(parsed.text, self.rules):
            ind.append((r.weight, r.description or r.id, r.group, r.critical))

        secrets = secret_hits(parsed.full_text)
        egress = parsed.intent == "network" or (parsed.intent in ("shell", "mutate", "other") and is_egress(parsed.text))
        if secrets and egress:
            ind.append((0.95, "a credential is being sent off the machine", "secrets", True))
        elif secrets and parsed.intent == "shell":
            ind.append((0.3, "a credential appears in a command line", "secrets", False))
        if egress and any(g == "secrets" for _, _, g, _ in ind) and not (secrets and egress):
            ind.append((0.75, "secrets and an outbound transfer in the same call (exfiltration)", "secrets", False))
        if parsed.intent == "delete" and not parsed.write_paths:
            ind.append((0.55, f"{call.tool} deletes something AIPS cannot checkpoint or restore", "destructive", False))
        if egress and self._read_secrets_recently(call, now):
            ind.append((0.55, "outbound call shortly after reading credential files (possible exfiltration)",
                        "secrets", False))

        roots = [Path(r) for r in pol.workspace_roots] or ([Path(call.cwd)] if call.cwd else [])
        if roots and parsed.write_paths:
            outside = [p for p in parsed.write_paths if not any(_within(p, r) for r in roots)]
            if outside:
                ind.append((0.55, f"changes files outside the workspace: {', '.join(map(str, outside[:3]))}",
                            "scope", False))
        if pol.allow_domains:
            bad = [h for h in (urlparse(u).hostname or "" for u in parsed.urls)
                   if h and not _local(h) and not any(fnmatch.fnmatch(h, d) or h.endswith("." + d.lstrip("*."))
                                                      for d in pol.allow_domains)]
            if bad:
                ind.append((0.35, f"contacts unapproved domain(s): {', '.join(sorted(set(bad))[:3])}", "scope", False))

        same = self.store.count(agent, now - cfg.loop_window_s, fingerprint=fp)
        if same + 1 >= cfg.loop_block:
            ind.append((0.8, f"same call repeated {same + 1} times in {cfg.loop_window_s:.0f}s (runaway loop)",
                        "erratic", False))
        elif same + 1 >= cfg.loop_flag:
            ind.append((0.35, f"same call repeated {same + 1} times in {cfg.loop_window_s:.0f}s", "erratic", False))
        rate = self.store.count(agent, now - 60.0) + 1
        if rate > pol.max_calls_per_min:
            ind.append((0.4, f"{rate} calls in the last minute (limit {pol.max_calls_per_min})", "erratic", False))
        res = self.store.recent_results(agent, cfg.error_streak)
        if len(res) >= cfg.error_streak and not any(res):
            ind.append((0.3, f"the last {cfg.error_streak} calls all failed (erratic behaviour)", "erratic", False))
        if call.session_id and self.store.session_calls(call.session_id) >= pol.max_calls_per_session:
            force_ask.append(f"session exceeded its budget of {pol.max_calls_per_session} calls")

        p_benign = 1.0
        for w, *_ in ind:
            p_benign *= (1 - w)
        risk = round(1 - p_benign, 3)
        groups = {g for _, _, g, _ in ind}

        taint = self.store.tainted(call.session_id)
        if taint and (parsed.intent in ("shell", "network", "delete", "mutate") or risk >= cfg.flag_risk):
            force_ask.append(f"session read untrusted content with embedded instructions ({taint})")

        critical = any(c for *_, c in ind)
        if critical or risk >= cfg.block_risk:
            verdict = Verdict.BLOCK
        elif force_ask or risk >= cfg.ask_risk:
            verdict = Verdict.ASK
        elif risk >= cfg.flag_risk:
            verdict = Verdict.FLAG
        else:
            verdict = Verdict.ALLOW
        reasons = [f"[{g}] {r}" for _, r, g, _ in sorted(ind, key=lambda x: -x[0])] + [f"[ask] {a}" for a in force_ask]

        dec = AgentDecision(call_id, agent, verdict, risk, reasons, parsed.intent)
        if verdict != Verdict.BLOCK and parsed.write_paths:
            n, missed = self._checkpoint(call_id, agent, now, parsed)
            dec.checkpoints = n
            if missed and (groups & _DESTRUCTIVE_GROUPS or parsed.intent == "delete") and verdict != Verdict.ASK:
                dec.verdict = Verdict.ASK
                dec.reasons.append(f"[save] could not checkpoint {missed} file(s) first; a human must approve")
        self._record(call, dec, parsed, fp, now)

        if dec.verdict == Verdict.BLOCK:
            blocks = self.store.count(agent, now - cfg.freeze_window_s, verdicts=(Verdict.BLOCK.value,))
            if critical or blocks >= cfg.freeze_after_blocks:
                why = (f"critical action blocked: {reasons[0]}" if critical
                       else f"{blocks} blocked calls within {cfg.freeze_window_s / 60:.0f} min")
                if cfg.autonomous_freeze:
                    self.freeze(agent, why, now, by="agent.guard")
                    dec.frozen_now = True
                dec.reasons.append(f"[freeze] {why}")
        if dec.verdict != Verdict.ALLOW:
            dec.finding = self._finding(call, dec, groups, critical, now)
        return dec

    def _read_secrets_recently(self, call: ToolCall, now: float) -> bool:
        rows = self.store.calls(call.agent_id, now - self.config.exfil_window_s, session=call.session_id, limit=500)
        return any(any(r.startswith("[secrets]") for r in row.reasons) for row in rows)

    def _record(self, call: ToolCall, dec: AgentDecision, parsed: _Parsed, fp: str, now: float) -> None:
        self.store.add_call(CallRow(dec.call_id, call.agent_id, call.session_id, now, call.tool, parsed.intent,
                                    _clip(call.args), fp, dec.verdict.value, dec.risk, dec.reasons,
                                    dec.verdict != Verdict.ALLOW, False, None, False))
        if self.audit is not None and dec.verdict != Verdict.ALLOW:
            self.audit.append(self.name, f"agent.call.{dec.verdict.value}",
                              {"agent": call.agent_id, "call": dec.call_id, "tool": call.tool, "risk": dec.risk,
                               "reasons": dec.reasons[:6]})

    def _finding(self, call: ToolCall, dec: AgentDecision, groups: set[str], critical: bool, now: float) -> Finding:
        if groups & {"destructive", "remote_code", "secrets", "tampering", "privilege", "self_protection"} or critical:
            signal = "agent_harmful_action"
        elif any(r.startswith("[ask] session read untrusted") for r in dec.reasons):
            signal = "agent_injection"
        elif "erratic" in groups:
            signal = "agent_erratic"
        else:
            signal = "agent_policy_violation"
        sev = {Verdict.BLOCK: Severity.CRITICAL if critical else Severity.HIGH, Verdict.ASK: Severity.MEDIUM,
               Verdict.FLAG: Severity.LOW}.get(dec.verdict, Severity.INFO)
        conf = 0.95 if critical else max(0.5, min(0.97, dec.risk + 0.1))
        f = Finding(detector=self.name, category=Category.AGENT, severity=sev, confidence=conf,
                    asset_id=f"agent:{call.agent_id}", title=f"{signal.replace('_', ' ')}: {call.agent_id} {call.tool}",
                    description="; ".join(dec.reasons), created_at=now, signal=signal,
                    tags={"agent": call.agent_id, "key": call.agent_id, "call": dec.call_id},
                    evidence=[Evidence("tool_call", self.name, {"agent": call.agent_id, "tool": call.tool,
                                                                 "args": _clip(call.args, 2000), "verdict": dec.verdict.value,
                                                                 "risk": dec.risk, "reasons": dec.reasons}, now)])
        if self.on_finding:
            self.on_finding(f)
        return f

    # ----------------------------------------------------------------------------------------- results
    def record_result(self, call_id: str, success: bool, output: Any = None, ts: float | None = None) -> dict[str, Any]:
        """Report what a call returned. Output carrying injected instructions taints the session."""
        now = ts if ts is not None else self.clock.now()
        row = self.store.get_call(call_id)
        if row is None:
            return {"known": False}
        self.store.set_result(call_id, success, now)
        out: dict[str, Any] = {"known": True, "tainted": False}
        if output is not None:
            strings: list[str] = []
            _strings(output if not isinstance(output, (int, float, bool)) else str(output), strings, [200_000])
            hits = injection_hits("\n".join(strings))
            if hits and row.session:
                reason = f"{row.tool} output contained instructions aimed at the agent"
                self.store.taint(row.session, now, reason)
                self.store.flag_call(call_id, f"[injection] {reason}")
                out["tainted"] = True
                f = Finding(detector=self.name, category=Category.AGENT, severity=Severity.MEDIUM, confidence=0.7,
                            asset_id=f"agent:{row.agent}", title=f"agent injection: {row.agent} read instructions via "
                            f"{row.tool}", description=reason, created_at=now, signal="agent_injection",
                            tags={"agent": row.agent, "key": row.agent, "call": call_id},
                            evidence=[Evidence("tool_result", self.name, {"patterns": hits[:5]}, now)])
                if self.on_finding:
                    self.on_finding(f)
                if self.audit is not None:
                    self.audit.append(self.name, "agent.session.tainted", {"agent": row.agent, "call": call_id})
        return out

    # ----------------------------------------------------------------------------------------- save
    def _checkpoint(self, call_id: str, agent: str, now: float, parsed: _Parsed) -> tuple[int, int]:
        cfg = self.config
        n = missed = 0
        budget = cfg.checkpoint_max_bytes
        blob_root = self.store.blob_dir.resolve()
        create_ok = {str(p) for p in parsed.create_ok}
        for p in parsed.write_paths:
            try:
                if _within(p, blob_root):
                    continue
                files = [p] if p.is_file() else (sorted(x for x in p.rglob("*") if x.is_file()) if p.is_dir() else [])
                if not files:
                    if not p.exists() and str(p) in create_ok:
                        self.store.add_checkpoint(call_id, agent, now, str(p), False, None, None)
                        n += 1
                    continue
                for f in files[: cfg.checkpoint_max_files]:
                    size = f.stat().st_size
                    if size > budget:
                        missed += 1
                        continue
                    data = f.read_bytes()
                    budget -= len(data)
                    self.store.add_checkpoint(call_id, agent, now, str(f), True, self.store.put_blob(data), len(data))
                    n += 1
                missed += max(0, len(files) - cfg.checkpoint_max_files)
            except OSError:
                missed += 1
        return n, missed

    # ----------------------------------------------------------------------------------------- freeze
    def freeze(self, agent_id: str, reason: str, now: float | None = None, by: str = "L3") -> dict[str, Any]:
        self.store.freeze(agent_id, reason, now if now is not None else self.clock.now(), by)
        if self.audit is not None:
            self.audit.append(by, "agent.frozen", {"agent": agent_id, "reason": reason})
        return {"agent": agent_id, "frozen": True}

    def unfreeze(self, agent_id: str, by: str = "human", clear_taint_sessions: bool = True) -> bool:
        ok = self.store.unfreeze(agent_id)
        if clear_taint_sessions:
            for s in {r.session for r in self.store.calls(agent_id) if r.session}:
                self.store.clear_taint(s)
        if self.audit is not None:
            self.audit.append(by, "agent.unfrozen", {"agent": agent_id, "was_frozen": ok})
        return ok

    # ----------------------------------------------------------------------------------------- fix
    def revert(self, agent_id: str, since: float | None = None, by: str = "L3", dry_run: bool = False) -> RevertReport:
        """Undo what the agent did from its first suspicious call onward (or from ``since``)."""
        rows = [r for r in self.store.calls(agent_id, since or 0.0) if not r.reverted]
        if since is None:
            first = next((r.ts for r in rows if r.flagged), None)
            rows = [] if first is None else [r for r in rows if r.ts >= first]
        # a call is "done" if it was reported as executed; an allowed call whose result never arrived is still
        # reverted when it has checkpoints (restoring an unchanged file is harmless)
        with_ckpt = {c.call_id for c in self.store.checkpoints(agent=agent_id)}
        done = [r for r in rows if (r.executed and r.success is not False)
                or (not r.executed and r.verdict != Verdict.BLOCK.value and r.call_id in with_ckpt)]
        rid = "RV-" + uuid.uuid4().hex[:10]
        restored: list[str] = []
        removed: list[str] = []
        review: list[str] = []
        failed: list[str] = []
        entries: list[dict[str, Any]] = []
        ckpts = [c for r in done for c in self.store.checkpoints(call_id=r.call_id) if not c.restored]
        have_ckpt = {c.call_id for c in ckpts}
        undo_n = 0
        for r in done:
            if r.call_id in self._undo:
                continue
            if r.call_id not in have_ckpt and r.intent != "read" and r.executed:
                review.append(f"{r.tool} {_short(r.args)}")
        if dry_run:
            return RevertReport(rid, agent_id, [r.call_id for r in done], [c.path for c in ckpts if c.existed],
                                [c.path for c in ckpts if not c.existed], sum(1 for r in done if r.call_id in self._undo),
                                review, [])
        for c in sorted(ckpts, key=lambda c: -c.id):
            p = Path(c.path)
            try:
                before_existed = p.is_file()
                before = self.store.put_blob(p.read_bytes()) if before_existed else None
                if c.existed:
                    data = self.store.get_blob(c.blob or "")
                    p.parent.mkdir(parents=True, exist_ok=True)
                    tmp = p.with_name(p.name + ".aips-restore")
                    tmp.write_bytes(data)
                    tmp.replace(p)
                    restored.append(c.path)
                elif before_existed:
                    p.unlink()
                    removed.append(c.path)
                entries.append({"ckpt": c.id, "path": c.path, "before_existed": before_existed, "before": before})
            except (OSError, ValueError) as exc:
                failed.append(f"{c.path}: {exc}")
        for r in reversed(done):
            if r.call_id in self._undo:
                fn, kwargs, result = self._undo.pop(r.call_id)
                try:
                    fn(kwargs, result)
                    undo_n += 1
                except Exception as exc:  # noqa: BLE001 - report, keep reverting the rest
                    failed.append(f"undo {r.tool}: {exc}")
        self.store.mark_restored([e["ckpt"] for e in entries])
        self.store.mark_reverted([r.call_id for r in done])
        self.store.add_revert(rid, agent_id, self.clock.now(), by, entries)
        rep = RevertReport(rid, agent_id, [r.call_id for r in done], restored, removed, undo_n, review, failed)
        if self.audit is not None:
            self.audit.append(by, "agent.reverted", {"agent": agent_id, "revert": rid, "restored": len(restored),
                                                     "removed": len(removed), "undo_callbacks": undo_n,
                                                     "needs_review": review[:20], "failed": failed[:20]})
        return rep

    def undo_revert(self, revert_id: str) -> tuple[bool, str]:
        rv = self.store.get_revert(revert_id)
        if rv is None or rv["undone"]:
            return False, "unknown or already undone revert"
        bad = []
        for e in reversed(rv["entries"]):
            p = Path(e["path"])
            try:
                if e["before_existed"]:
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(self.store.get_blob(e["before"]))
                elif p.exists():
                    p.unlink()
            except (OSError, ValueError) as exc:
                bad.append(f"{p}: {exc}")
        self.store.mark_restored([e["ckpt"] for e in rv["entries"]], False)
        self.store.mark_revert_undone(revert_id)
        return not bad, f"undid revert {revert_id}" + (f"; failed: {'; '.join(bad)}" if bad else "")

    # ----------------------------------------------------------------------------------------- in-process
    def guarded(self, tool: str, fn: Callable[..., Any], *, agent_id: str, session_id: str | None = None,
                cwd: str | None = None, undo: Callable[[dict[str, Any], Any], Any] | None = None,
                approver: Callable[[ToolCall, AgentDecision], bool] | None = None) -> Callable[..., Any]:
        """Wrap a Python tool function so every call goes through the guard.

        ``undo(kwargs, result)`` reverses one call (used by ``revert``); ``approver(call, decision)`` is asked
        for ASK verdicts - without one, ASK is treated as BLOCK."""
        def wrapper(**kwargs: Any) -> Any:
            call = ToolCall(agent_id, tool, dict(kwargs), session_id, cwd)
            d = self.check(call)
            if d.verdict == Verdict.BLOCK or (d.verdict == Verdict.ASK and not (approver and approver(call, d))):
                raise ActionBlocked(d)
            try:
                result = fn(**kwargs)
            except Exception:
                self.record_result(d.call_id, False)
                raise
            self.record_result(d.call_id, True, result)
            if undo is not None:
                self._undo[d.call_id] = (undo, dict(kwargs), result)
            return result
        wrapper.__name__ = getattr(fn, "__name__", tool)
        wrapper.__doc__ = fn.__doc__
        return wrapper

    # ----------------------------------------------------------------------------------------- views
    def snapshot(self) -> dict[str, Any]:
        s = self.store.stats()
        s["frozen_agents"] = self.store.frozen()
        s["agents"] = self.store.agents()
        return s

    def history(self, agent_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.store.calls(agent_id)[-limit:]
        return [{"call": r.call_id, "agent": r.agent, "ts": r.ts, "tool": r.tool, "intent": r.intent,
                 "verdict": r.verdict, "risk": r.risk, "reasons": r.reasons, "executed": r.executed,
                 "success": r.success, "reverted": r.reverted, "args": _short(r.args)} for r in rows]


def _dedupe(paths: list[Path]) -> list[Path]:
    seen, out = set(), []
    for p in paths:
        k = os.path.normcase(str(p))
        if k not in seen:
            seen.add(k)
            out.append(p)
    return out


def _within(p: Path, root: Path) -> bool:
    try:
        a = os.path.normcase(os.path.abspath(p))
        b = os.path.normcase(os.path.abspath(root))
        return os.path.commonpath([a, b]) == b
    except ValueError:                 # different drives on Windows
        return False


def _local(host: str) -> bool:
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")


def _clip(args: dict[str, Any], limit: int = 20_000) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in (args or {}).items():
        if isinstance(v, str) and len(v) > limit:
            out[k] = v[:limit] + f"...[{len(v) - limit} more chars]"
        elif isinstance(v, (str, int, float, bool)) or v is None:
            out[k] = v
        else:
            s = json.dumps(v, default=str)
            out[k] = v if len(s) <= limit else s[:limit] + "...]"
    return out


def _short(args: dict[str, Any]) -> str:
    for k in SHELL_KEYS + PATH_KEYS + URL_KEYS:
        if isinstance(args.get(k), str):
            v = args[k].replace("\n", " ")
            return v[:160] + ("..." if len(v) > 160 else "")
    s = json.dumps(args, default=str)
    return s[:160] + ("..." if len(s) > 160 else "")
