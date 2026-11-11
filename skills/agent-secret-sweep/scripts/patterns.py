"""Secret detection patterns for agent-written config files.

Two detector classes, mirroring how real secret scanners work:

  PROVIDER  - a credential in a known vendor format (AKIA..., ghp_..., sk-...).
              Self-evidencing: the format alone is enough to call it a secret.

  EMBEDDED  - a password or token sitting inside a shell command
              (PGPASSWORD=, sshpass -p, mysql -p, bearer headers, URIs).
              These are ordinary words in ordinary command lines, which is
              exactly why gitleaks/TruffleHog miss them. To keep the false
              positive rate sane we only call one a secret when a PUBLIC host
              appears on the same line; otherwise it is reported as "review".

Nothing here mutates state. Import and call `scan_text`.
"""

from __future__ import annotations

import re
from typing import Any, Sequence

# --- provider formats: match == secret -------------------------------------

PROVIDER_PATTERNS: tuple[tuple[str, str], ...] = (
    ("aws-access-key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("github-token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ("github-fine-grained-pat", r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    ("gitlab-token", r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    ("anthropic-key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
    ("openai-format-key", r"\bsk-(?!ant-)[A-Za-z0-9_\-]{20,}\b"),
    ("slack-token", r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
    ("stripe-live-key", r"\b[sr]k_live_[A-Za-z0-9]{20,}\b"),
    ("square-token", r"\bEAAA[A-Za-z0-9_\-]{20,}\b"),
    ("npm-token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("supabase-personal-token", r"\bsbp_[A-Za-z0-9]{40}\b"),
    ("google-api-key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("huggingface-token", r"\bhf_[A-Za-z0-9]{30,}\b"),
    ("jwt-or-supabase-service-key",
     r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ("private-key-block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("slack-webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/+]{20,}"),
)

# --- secrets embedded in shell commands: need a public host to confirm -----

EMBEDDED_PATTERNS: tuple[tuple[str, str], ...] = (
    ("pgpassword-env", r"PGPASSWORD=(?P<v>[^\s'\"\\]{4,})"),
    ("mysql-pwd-env", r"MYSQL_PWD=(?P<v>[^\s'\"\\]{4,})"),
    ("mysql-inline-p", r"\bmysql(?:dump)?\b[^\n]{0,120}?\s-p(?P<v>[^\s'\"\-][^\s'\"]{3,})"),
    ("sshpass", r"\bsshpass\s+-p\s*(?P<v>[^\s'\"]{3,})"),
    ("password-flag", r"--password[=\s]+(?P<v>[^\s'\"$]{4,})"),
    ("curl-basic-auth", r"(?:\s-u|--user)\s+(?P<v>[^\s'\":]+:[^\s'\"]{3,})"),
    ("bearer-header", r"[Bb]earer\s+(?P<v>[A-Za-z0-9._~+/=\-]{16,})"),
    ("basic-header", r"[Bb]asic\s+(?P<v>[A-Za-z0-9+/]{16,}={0,2})"),
    ("uri-credentials",
     r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|ftp|https?)://"
     r"(?:[^:@/\s]{1,64}):(?P<v>[^@/\s]{3,})@"),
    ("assigned-credential",
     r"(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?key|auth[_-]?token"
     r"|client[_-]?secret|db[_-]?pass(?:word)?|password|passwd|token)"
     r"\s*[=:]\s*[\"']?(?P<v>[^\s\"'&;|,}\\]{8,})"),
)

# --- noise suppression -----------------------------------------------------

PLACEHOLDER_SUBSTRINGS: tuple[str, ...] = (
    "example", "changeme", "change-me", "placeholder", "your-", "your_",
    "yourpassword", "redacted", "dummy", "sample", "insert", "replace",
    "todo", "fixme", "notreal", "fake", "mock", "test-token", "testtoken",
    "xxxx", "abc123", "foobar", "<", ">", "{{", "}}", "...",
)

PLACEHOLDER_EXACT: tuple[str, ...] = (
    "password", "passwd", "secret", "token", "apikey", "api_key", "key",
    "admin", "root", "postgres", "mysql", "guest", "user", "none", "null",
    "true", "false", "hunter2", "letmein", "123456", "password123",
)

# A value that is really a shell/env indirection is the FIX, not the problem.
INDIRECTION_RE = re.compile(
    r"^(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|%[A-Za-z_][A-Za-z0-9_]*%"
    r"|\$\([^)]*\)|`[^`]*`)$"
)

LOCAL_HOST_RE = re.compile(
    r"(?i)^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[?::1\]?"
    r"|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+"
    r"|host\.docker\.internal|.*\.local|.*\.internal|.*\.test|.*\.invalid"
    r"|.*\.example\.com|example\.(?:com|org|net))$"
)

HOST_RE = re.compile(
    r"(?:(?:-h|--host|--hostname)[=\s]+|@|//)"
    r"(?P<h>[A-Za-z0-9](?:[A-Za-z0-9._\-]*[A-Za-z0-9])?)"
)


def is_placeholder(value: str) -> bool:
    """True when a matched value is obviously not a live credential."""
    low = value.strip().strip("\"'").lower()
    if len(low) < 6:
        return True
    if INDIRECTION_RE.match(value.strip()):
        return True
    if low in PLACEHOLDER_EXACT:
        return True
    if any(token in low for token in PLACEHOLDER_SUBSTRINGS):
        return True
    if len(set(low)) <= 2:          # "aaaaaaaa", "********"
        return True
    if re.fullmatch(r"[*x\-_.]+", low):
        return True
    return False


def public_hosts(line: str) -> tuple[str, ...]:
    """Public (non-loopback, non-RFC1918, non-reserved) hosts named on a line."""
    found = (m.group("h") for m in HOST_RE.finditer(line))
    return tuple(
        h for h in found
        if "." in h and not LOCAL_HOST_RE.match(h)
    )


def mask(value: str) -> str:
    """Render a secret safely for a report: first 3 chars, length, last 2."""
    clean = value.strip().strip("\"'")
    if len(clean) <= 6:
        return "*" * len(clean)
    return f"{clean[:3]}{'*' * (len(clean) - 5)}{clean[-2:]}"


def scan_text(text: str, origin: str) -> list[dict[str, Any]]:
    """Yield finding dicts for one string. `origin` describes where it came from.

    verdict is one of:
      "secret" - provider format, or embedded credential aimed at a public host
      "review" - embedded credential with no public host on the line
    """
    findings: list[dict[str, Any]] = []
    for name, pattern in PROVIDER_PATTERNS:
        for m in re.finditer(pattern, text):
            value = m.group(0)
            if is_placeholder(value) and name != "private-key-block":
                continue
            findings.append(_finding(name, value, "secret", origin, text, ()))

    for name, pattern in EMBEDDED_PATTERNS:
        for m in re.finditer(pattern, text):
            value = m.group("v")
            if is_placeholder(value):
                continue
            hosts = public_hosts(text)
            verdict = "secret" if hosts else "review"
            findings.append(_finding(name, value, verdict, origin, text, hosts))

    return _dedupe(findings)


def _finding(
    rule: str, value: str, verdict: str, origin: str,
    text: str, hosts: Sequence[str],
) -> dict[str, Any]:
    return {
        "rule": rule,
        "verdict": verdict,
        "masked": mask(value),
        "value_len": len(value),
        "origin": origin,
        "hosts": list(hosts),
        "excerpt": _excerpt(text, value),
    }


def _excerpt(text: str, value: str) -> str:
    """One-line context with the secret masked out."""
    redacted = text.replace(value, mask(value))
    flat = " ".join(redacted.split())
    return flat if len(flat) <= 220 else flat[:217] + "..."


def _dedupe(findings: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse overlapping matches of the same value, keeping the strongest."""
    best: dict[tuple[str, str, int], dict[str, Any]] = {}
    for f in findings:
        key = (f["origin"], f["masked"], f["value_len"])
        prior = best.get(key)
        if prior is None or (prior["verdict"] == "review" and f["verdict"] == "secret"):
            best[key] = f
    return list(best.values())
