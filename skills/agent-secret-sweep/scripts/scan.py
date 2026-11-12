#!/usr/bin/env python3
"""Read-only sweep for secrets written into agent config and memory files.

Finds the files coding agents write approvals and notes into, looks for
credentials inside them, and grades each hit by how exposed it actually is
(committed and pushed > committed > one commit away > local only).

This script NEVER writes, edits, stages or deletes anything. Remediation is
a separate, explicitly-invoked script.

Usage:
    python3 scan.py [ROOT ...] [--json OUT] [--depth N] [--all]

    ROOT      directories to sweep (default: $HOME, depth-limited)
    --json    write the full machine-readable report to this path
    --depth   max directory depth below each root (default 6)
    --all     include "review"-grade hits in the human summary
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))
from patterns import scan_text  # noqa: E402

# Files agents write that routinely end up holding credentials.
#
# .claude.json deserves special mention: it is where Claude Code stores MCP
# server definitions, including auth headers and tokens. It is the single
# most credential-dense file most users have. It normally sits in $HOME,
# outside any repository, so it rarely leaks via git - but it is a prime
# target for credential-harvesting malware, so it must still be reported.
TARGET_NAMES: tuple[str, ...] = (
    ".claude.json",
    ".claude/settings.local.json",
    ".claude/settings.json",
    ".cursor/mcp.json",
    ".gemini/settings.json",
    ".vscode/settings.json",
    ".mcp.json",
    "CLAUDE.md",
    "AGENTS.md",
    "MEMORY.md",
)

# Directories never worth descending into.
SKIP_DIRS: frozenset[str] = frozenset({
    ".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
    "target", ".next", ".cache", "Library", "Applications", ".Trash",
    "site-packages", ".terraform", "vendor", ".gradle", ".m2", "Pods",
})

SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low")


@dataclass(frozen=True)
class GitFacts:
    """What git knows about one file. All fields are best-effort.

    `ignored_by` matters more than `ignored`. A rule in the repo's own
    .gitignore travels to every clone and fork. A rule in the user's global
    ignore file or .git/info/exclude protects this machine only - which is
    exactly the gap that leaks these files from a teammate's clone.
    """

    repo_root: str | None = None
    tracked: bool = False
    in_history: bool = False
    has_remote: bool = False
    ignored: bool = False
    ignored_by: str | None = None

    @property
    def ignore_travels(self) -> bool:
        """True only when the ignore rule ships with the repository.

        Only a committed `.gitignore` travels. Three sources do not, and all
        three look reassuring locally:

          - the user's global ignore file (absolute path)
          - .git/info/exclude (per-clone, never committed)
          - any file named by `core.excludesFile`, even one inside the repo,
            because the git config that activates it is not committed - so a
            clone silently loses the rule
        """
        if not self.ignored or not self.ignored_by:
            return False
        source = Path(self.ignored_by)
        if source.is_absolute() or ".git/info/exclude" in self.ignored_by:
            return False
        return source.name == ".gitignore"


@dataclass(frozen=True)
class FileReport:
    """One scanned file and everything found in it."""

    path: str
    git: GitFacts
    findings: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    @property
    def severity(self) -> str:
        return grade(self.git, self.findings)


# --------------------------------------------------------------------------
# discovery
# --------------------------------------------------------------------------


def walk_targets(root: Path, max_depth: int) -> Iterator[Path]:
    """Yield existing target files under `root`, pruning noisy directories."""
    root = root.expanduser().resolve()
    base_depth = len(root.parts)
    for dirpath, dirnames, _ in os.walk(root, topdown=True, onerror=lambda e: None):
        here = Path(dirpath)
        if len(here.parts) - base_depth >= max_depth:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in TARGET_NAMES:
            candidate = here / name
            if candidate.is_file():
                yield candidate


def discover(roots: Sequence[Path], max_depth: int) -> list[Path]:
    """Deduplicated, sorted list of target files across all roots."""
    seen: set[Path] = set()
    for root in roots:
        for path in walk_targets(root, max_depth):
            seen.add(path.resolve())
    return sorted(seen)


# --------------------------------------------------------------------------
# git context
# --------------------------------------------------------------------------


def _git(args: Sequence[str], cwd: Path) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=20,
        )
        return proc.returncode, proc.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def git_facts(path: Path) -> GitFacts:
    """Establish how exposed a file is, from git's point of view."""
    parent = path.parent
    code, root = _git(["rev-parse", "--show-toplevel"], parent)
    if code != 0 or not root:
        return GitFacts()

    # Both sides must be resolved: on macOS /tmp is a symlink to /private/tmp,
    # so an unresolved path is not a subpath of what git reports.
    repo = Path(root).resolve()
    try:
        rel = str(path.resolve().relative_to(repo))
    except ValueError:
        return GitFacts()
    tracked = _git(["ls-files", "--error-unmatch", rel], repo)[0] == 0
    ign_code, ign_out = _git(["check-ignore", "-v", "--", rel], repo)
    has_remote = bool(_git(["remote"], repo)[1])
    hist_code, hist = _git(
        ["log", "--oneline", "-1", "--all", "--", rel], repo
    )
    return GitFacts(
        repo_root=str(repo),
        tracked=tracked,
        in_history=bool(hist_code == 0 and hist),
        has_remote=has_remote,
        ignored=ign_code == 0,
        ignored_by=ign_out.split(":", 1)[0] if ign_code == 0 and ign_out else None,
    )


# --------------------------------------------------------------------------
# content extraction
# --------------------------------------------------------------------------


def iter_json_strings(node: Any, trail: str = "$") -> Iterator[tuple[str, str]]:
    """Walk a parsed JSON document yielding (json_path, string_value)."""
    if isinstance(node, str):
        yield trail, node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from iter_json_strings(value, f"{trail}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from iter_json_strings(value, f"{trail}[{index}]")


def scan_file(path: Path) -> tuple[dict[str, Any], ...]:
    """Findings for one file, routed by JSON vs plain text."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ()

    if path.suffix == ".json":
        try:
            return tuple(_scan_json(json.loads(text)))
        except json.JSONDecodeError:
            pass  # malformed JSON: fall through to line scanning
    return tuple(_scan_lines(text))


def _scan_json(document: Any) -> Iterator[dict[str, Any]]:
    for json_path, value in iter_json_strings(document):
        for finding in scan_text(value, json_path):
            yield {**finding, "container": "json", "rule_string": value}


def _scan_lines(text: str) -> Iterator[dict[str, Any]]:
    for number, line in enumerate(text.splitlines(), start=1):
        for finding in scan_text(line, f"line {number}"):
            yield {**finding, "container": "text", "rule_string": line.strip()}


# --------------------------------------------------------------------------
# grading
# --------------------------------------------------------------------------


def grade(git: GitFacts, findings: Sequence[dict[str, Any]]) -> str:
    """Severity is exposure x confidence, not confidence alone."""
    if not findings:
        return "none"
    confirmed = any(f["verdict"] == "secret" for f in findings)
    if git.tracked or git.in_history:
        return "critical" if confirmed else "high"
    # Only a repo-local .gitignore rule actually protects clones and forks.
    if git.repo_root and not git.ignore_travels:
        return "high" if confirmed else "medium"
    return "medium" if confirmed else "low"


EXPOSURE_TEXT: dict[str, str] = {
    "critical": "committed to git - history, forks and clones keep it even "
                "if you delete the file",
    "high": "in a git repo with no .gitignore rule that travels - one "
            "`git add .`, or one clone on another machine, from exposure",
    "medium": "local only - still a ready-made credential list for malware",
    "low": "local only, unconfirmed match",
}


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------


def build_report(paths: Sequence[Path]) -> list[FileReport]:
    """Scan every path and keep only files that produced findings."""
    reports = (
        FileReport(path=str(p), git=git_facts(p), findings=scan_file(p))
        for p in paths
    )
    hits = [r for r in reports if r.findings]
    return sorted(hits, key=lambda r: SEVERITY_ORDER.index(r.severity))


def print_summary(reports: Sequence[FileReport], scanned: int, show_all: bool) -> None:
    print(f"\n  Scanned {scanned} agent file(s).")
    if not reports:
        print("  No credentials found. Nothing to fix.\n")
        return

    confirmed = sum(
        1 for r in reports for f in r.findings if f["verdict"] == "secret"
    )
    print(f"  {len(reports)} file(s) with findings; {confirmed} confirmed secret(s).\n")

    for report in reports:
        shown = [
            f for f in report.findings
            if show_all or f["verdict"] == "secret"
        ]
        if not shown:
            continue
        print(f"  [{report.severity.upper()}] {report.path}")
        print(f"      exposure: {EXPOSURE_TEXT[report.severity]}")
        if report.git.repo_root:
            flags = ",".join(
                name for name, on in (
                    ("tracked", report.git.tracked),
                    ("in-history", report.git.in_history),
                    ("has-remote", report.git.has_remote),
                ) if on
            ) or "untracked"
            print(f"      git: {flags}  (repo {report.git.repo_root})")
            if report.git.ignored and not report.git.ignore_travels:
                print(f"      WARNING: ignored only by {report.git.ignored_by} "
                      f"- that rule does NOT travel to clones or forks")
        for finding in shown:
            tag = "SECRET" if finding["verdict"] == "secret" else "review"
            hosts = f" -> {', '.join(finding['hosts'])}" if finding["hosts"] else ""
            print(f"      - {tag} {finding['rule']}: {finding['masked']}{hosts}")
            print(f"        at {finding['origin']}: {finding['excerpt']}")
        print()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="*", default=[str(Path.home())])
    parser.add_argument("--json", dest="json_out", default=None)
    parser.add_argument("--depth", type=int, default=6)
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args(argv)

    roots = [Path(r) for r in (args.roots or [str(Path.home())])]
    print(f"  Sweeping: {', '.join(str(r) for r in roots)} (depth {args.depth})")
    paths = discover(roots, args.depth)
    reports = build_report(paths)
    print_summary(reports, len(paths), args.all)

    if args.json_out:
        payload = {
            "scanned": len(paths),
            "files": [
                {
                    "path": r.path,
                    "severity": r.severity,
                    "git": r.git.__dict__,
                    "findings": list(r.findings),
                }
                for r in reports
            ],
        }
        # The report must keep each rule verbatim so remediation can match
        # and remove it - which makes the report itself a credential file.
        # Lock it down and say so, rather than leaving a world-readable copy
        # in a shared temp directory.
        out = Path(args.json_out)
        out.write_text(json.dumps(payload, indent=2))
        try:
            out.chmod(0o600)
        except OSError:
            pass
        print(f"  Full report: {out}")
        print("  WARNING: that report holds the secrets in cleartext "
              "(mode 600). Delete it when you are done.\n")

    confirmed = any(
        f["verdict"] == "secret" for r in reports for f in r.findings
    )
    high = any(r.severity in ("critical", "high") for r in reports)
    return 1 if (confirmed or high) else 0


if __name__ == "__main__":
    raise SystemExit(main())
