"""What makes an AI agent's tool call harmful: the built-in rule set.

Each rule is a regular expression over the text of a tool call (its command, query, path, URL, content...).
A rule has a weight (its contribution to the call's risk, combined by noisy-OR like the identity guard) and
may be *critical*: a critical match blocks the call no matter what else is true, and counts toward freezing
the agent. Rules are grouped by what they protect against so a finding says *why* a call was stopped.

The rules are deliberately readable rather than clever. They are a first line of defence, not a sandbox: an
agent that is determined to evade text rules can encode a command. The guard therefore also judges
*behaviour* (loops, bursts, error storms, scope, untrusted-input taint), keeps checkpoints so damage can be
undone, and can freeze the agent outright - see ``guard.py`` and docs/AGENTS.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class HarmRule:
    id: str
    group: str            # destructive | remote_code | secrets | tampering | privilege | self_protection
    pattern: str
    weight: float
    critical: bool = False
    description: str = ""

    def compiled(self) -> re.Pattern[str]:
        return _compile(self.pattern)


_CACHE: dict[str, re.Pattern[str]] = {}


def _compile(p: str) -> re.Pattern[str]:
    c = _CACHE.get(p)
    if c is None:
        c = _CACHE[p] = re.compile(p, re.IGNORECASE | re.MULTILINE)
    return c


_RM_RF = r"\brm\s+(?:-[a-z]*(?:rf|fr)[a-z]*|-r\s+-f|-f\s+-r|--recursive\s+--force|--force\s+--recursive)"

DEFAULT_RULES: list[HarmRule] = [
    # -- destroying data or systems --------------------------------------------------------------------------
    HarmRule("rm_rf_root", "destructive", _RM_RF + r"\s+(?:--no-preserve-root\s+)?(?:/|/\*|~/?|\*|\$HOME/?|\.\.?/?)(?:\s|;|&|\||$)",
             0.95, True, "recursive force delete of a root, home or whole working directory"),
    HarmRule("rm_rf", "destructive", _RM_RF, 0.45, description="recursive force delete"),
    HarmRule("ps_remove_drive", "destructive",
             r"remove-item\b[^\n|;]*\s['\"]?[a-z]:\\?\*?['\"]?(?:\s|$)[^\n]*-recurse|remove-item\b[^\n|;]*-recurse[^\n|;]*\s['\"]?[a-z]:\\?\*?['\"]?(?:\s|$)",
             0.95, True, "recursive delete of a whole drive"),
    HarmRule("ps_remove_recurse", "destructive", r"remove-item\b[^\n|;]*-recurse", 0.4,
             description="recursive delete (PowerShell)"),
    HarmRule("cmd_wipe", "destructive", r"\b(?:rd|rmdir)\s+/s\s+/q\s+[a-z]:\\?(?:\s|$)|\bdel\s+/[fsq](?:\s+/[fsq])*\s+[a-z]:\\|\bformat\s+[a-z]:",
             0.95, True, "wipe or format a drive (cmd)"),
    HarmRule("disk_overwrite", "destructive", r"\bmkfs(?:\.\w+)?\b|\bdd\b[^\n]*\bof=/dev/(?:sd|nvme|hd|xvd|disk)|>\s*/dev/(?:sd|nvme|hd)[a-z]",
             0.95, True, "overwrite a disk or file system"),
    HarmRule("fork_bomb", "destructive", r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", 0.95, True, "fork bomb"),
    HarmRule("sql_drop", "destructive", r"\bdrop\s+(?:table|database|schema)\b", 0.8, description="drop a table/database"),
    HarmRule("sql_truncate", "destructive", r"\btruncate\s+(?:table\s+)?\w", 0.65, description="truncate a table"),
    HarmRule("sql_delete_all", "destructive", r"\bdelete\s+from\s+[\w.\"`\[\]]+\s*(?:;|$)", 0.65,
             description="DELETE without a WHERE clause"),
    HarmRule("git_force_push", "destructive", r"\bgit\s+push\b[^\n]*(?:--force\b|--force-with-lease\b|\s-f\b|\s\+\w)", 0.6,
             description="rewrite shared git history"),
    HarmRule("git_destroy_local", "destructive", r"\bgit\s+(?:reset\s+--hard|clean\s+-[a-z]*f|checkout\s+--\s+\.|branch\s+-D)\b",
             0.4, description="discard local work in git"),
    HarmRule("git_rewrite", "destructive", r"\bgit\s+(?:filter-branch|filter-repo)\b", 0.5, description="rewrite git history"),
    HarmRule("infra_destroy", "destructive",
             r"\bterraform\s+destroy\b|\bkubectl\s+delete\s+(?:ns|namespace|--all|all\b)|\bgcloud\s+projects\s+delete\b"
             r"|\baws\s+s3\s+rb\b|\baws\s+s3\s+rm\b[^\n]*--recursive|\baz\s+group\s+delete\b|\bhelm\s+uninstall\b",
             0.85, description="destroy cloud infrastructure"),
    HarmRule("cloud_delete", "destructive", r"\b(?:gcloud|aws|az)\b[^\n]*\s(?:delete|remove|rm|terminate-instances)\b", 0.45,
             description="delete a cloud resource"),
    # -- running code from the internet ----------------------------------------------------------------------
    HarmRule("pipe_to_shell", "remote_code",
             r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]*\|\s*iex\b"
             r"|\bbase64\s+(?:-d|--decode)\b[^\n]*\|\s*(?:ba)?sh\b",
             0.85, description="download and run code in one step"),
    HarmRule("eval_expression", "remote_code", r"\binvoke-expression\b|\biex\s*\(", 0.4, description="evaluate a string as code"),
    # -- reaching for secrets -------------------------------------------------------------------------------
    HarmRule("secret_files", "secrets",
             r"(?:^|[\s/\\'\"=])(?:\.env(?:\.(?!example\b|sample\b|template\b|dist\b)\w+)?|id_rsa|id_ed25519|id_ecdsa|\.git-credentials|\.npmrc|\.pypirc|credentials\.json"
             r"|application_default_credentials\.json|\.netrc)(?:$|[\s'\"])|\.aws[/\\]credentials|\.ssh[/\\]|\.kube[/\\]config"
             r"|\.docker[/\\]config\.json|\\login data\b|/login data\b|\bcookies\.sqlite\b",
             0.4, description="credential or key file"),
    HarmRule("secret_env_dump", "secrets", r"(?<![.\w-])(?:printenv|env)\s*(?:\||>|$)|\bget-childitem\s+env:|\bgci\s+env:|\bset\s*>\s*\S",
             0.3, description="dump environment variables"),
    # -- weakening security controls ------------------------------------------------------------------------
    HarmRule("disable_defender", "tampering",
             r"set-mppreference\b[^\n]*-disable\w*\s+\$?true|\bnetsh\s+advfirewall\s+set\s+\w+\s+state\s+off\b|\bufw\s+disable\b"
             r"|\biptables\s+-F\b|\bsetenforce\s+0\b|\bsystemctl\s+(?:stop|disable|mask)\s+(?:auditd|rsyslog|firewalld|apparmor)\b"
             r"|\bauditctl\s+-D\b|\bwevtutil\s+cl\b|\bclear-eventlog\b",
             0.85, description="disable security or audit controls"),
    HarmRule("world_writable", "tampering", r"\bchmod\s+(?:-R\s+)?(?:0?777|a\+rwx)\b", 0.4, description="make files world-writable"),
    HarmRule("skip_checks", "tampering", r"--no-verify\b|--no-gpg-sign\b|-c\s+commit\.gpgsign=false", 0.35,
             description="skip commit hooks or signing"),
    HarmRule("erase_history", "tampering", r"\bhistory\s+-c\b|\bclear-history\b|\bunset\s+HISTFILE\b", 0.4,
             description="erase shell history"),
    HarmRule("delete_git_dir", "tampering", r"\b(?:rm|del|remove-item|rd|rmdir)\b[^\n]*[\s/\\'\"]\.git(?:[\s/\\'\"]|$)", 0.6,
             description="delete a repository's history"),
    HarmRule("crontab_wipe", "tampering", r"\bcrontab\s+-r\b", 0.5, description="remove all scheduled jobs"),
    # -- gaining privilege ----------------------------------------------------------------------------------
    HarmRule("sudo", "privilege", r"(?:^|[;&|]\s*)sudo\b|\brunas\s+/user:|start-process\b[^\n]*-verb\s+runas", 0.3,
             description="run as administrator"),
    HarmRule("grant_owner", "privilege", r"add-iam-policy-binding\b[^\n]*roles/(?:owner|editor|iam\.\w*admin)"
             r"|\baws\s+iam\s+attach-\w+-policy\b[^\n]*AdministratorAccess|\brole\s+assignment\s+create\b[^\n]*\bowner\b",
             0.7, description="grant owner/admin rights"),
    # -- attacking the guard itself -------------------------------------------------------------------------
    HarmRule("guard_tamper", "self_protection",
             r"\baips\s+agent\s+(?:unfreeze|reset|forget)\b|\.aips-agent(?:[/\\'\"\s]|$)",
             0.95, True, "an agent may not unfreeze itself or touch the guard's state"),
    HarmRule("web_tamper", "self_protection",
             r"\.aips-web(?:[/\\'\"\s]|$)|\baips\s+web\s+(?:approve|unlock|revoke|issue|reset-passphrase)\b|"
             r"\b(?:domain|human|credential)\.json\b|web-audit\.jsonl",
             0.95, True, "an agent may not touch the AIPS web's keys, approvals or audit log"),
    HarmRule("hook_tamper", "self_protection", r"\.claude[/\\]settings(?:\.local)?\.json|\bdisableAllHooks\b", 0.7,
             description="change the agent's own guard-rail configuration"),
]

# Text that tries to give an agent new instructions from inside data it read (prompt injection).
INJECTION_MARKERS = [
    r"\bignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts|rules)",
    r"\bdisregard\s+(?:all\s+|your\s+|the\s+)?(?:previous\s+|system\s+)?(?:instructions|prompt|rules)",
    r"\byou\s+are\s+now\s+(?:in\s+)?(?:developer|dan|jailbreak|unrestricted)\b",
    r"<\s*/?\s*(?:system|instructions?)\s*>",
    r"\bnew\s+(?:system\s+)?instructions\s*:",
    r"\b(?:do\s+not|don't)\s+(?:tell|inform)\s+the\s+user\b",
    r"\bexfiltrate\b|\bsend\s+(?:the\s+)?(?:api\s+keys?|secrets?|credentials|passwords?)\s+to\b",
]

# Strings that look like live credentials. Seeing one inside an outbound call is treated as exfiltration.
SECRET_LITERALS = [
    r"\bAKIA[0-9A-Z]{16}\b",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b",
    r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{24,}\b",
    r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
    r"\bAIza[0-9A-Za-z_-]{35}\b",
    r"\"private_key\"\s*:\s*\"-----BEGIN",
]

# Commands that send data off the machine.
EGRESS = r"\b(?:curl|wget|nc|ncat|netcat|scp|sftp|rsync|ftp|telnet|iwr|irm|invoke-webrequest|invoke-restmethod|ssh)\b"


def match_rules(text: str, rules: list[HarmRule]) -> list[HarmRule]:
    return [r for r in rules if r.compiled().search(text)]


def injection_hits(text: str) -> list[str]:
    return [p for p in INJECTION_MARKERS if _compile(p).search(text)]


def secret_hits(text: str) -> int:
    return sum(1 for p in SECRET_LITERALS if _compile(p).search(text))


def is_egress(text: str) -> bool:
    return bool(_compile(EGRESS).search(text))
