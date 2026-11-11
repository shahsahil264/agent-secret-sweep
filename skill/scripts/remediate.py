#!/usr/bin/env python3
"""Remove secret-bearing permission rules without breaking the agent.

Design rules, in priority order:

  1. Never break Claude Code. Every edit keeps the file valid JSON with its
     original structure; only the targeted strings are removed. The file is
     re-parsed and diffed after writing, and the backup is restored
     automatically if anything looks wrong.
  2. Never silently broaden permissions. Removing an approval is safe: Claude
     simply asks again next time, which is its normal behaviour. REPLACING a
     literal rule with a wildcard pattern would grant MORE than before, so
     this script never does that - it only prints a suggestion for you.
  3. Dry run by default. Nothing is written without --apply.
  4. Never touch prose. Markdown notes and transcripts are reported, not
     auto-edited, because rewriting prose mechanically is how you lose work.
  5. Never rotate, commit, or push. Those are human decisions.

Usage:
    python3 remediate.py REPORT.json                 # preview (default)
    python3 remediate.py REPORT.json --apply         # write changes
    python3 remediate.py REPORT.json --apply --include-review
    python3 remediate.py REPORT.json --apply --gitignore   # also fix .gitignore
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

RULE_LISTS: tuple[str, ...] = ("allow", "ask", "deny")
GITIGNORE_ENTRIES: tuple[str, ...] = (
    ".claude/settings.local.json",
    ".claude/*.local.json",
    ".claude/*.bak-*",
)

# Backups hold the secrets in cleartext, so they must never land inside a
# repository where the next `git add .` would commit them.
BACKUP_DIR: Path = Path.home() / ".cache" / "agent-secret-sweep" / "backups"

# A leaked credential comes in two shapes, and they need opposite fixes.
#
# APPROVAL RECORDS store a transcript of commands the user approved. Nothing
# authenticates with them, so the secret-bearing line can simply be deleted:
# the agent just asks for permission again next time.
#
# CREDENTIAL STORES are live wiring. An MCP server reads these values at
# startup and authenticates with them on every call. Editing them breaks the
# server, so the fix is never to change the file - it is to make git blind
# to it. The bytes stay identical and everything keeps working.
CREDENTIAL_STORE_NAMES: frozenset[str] = frozenset({
    ".mcp.json", "mcp.json", ".claude.json",
})


@dataclass(frozen=True)
class Plan:
    """What will be done to one file."""

    path: Path
    doomed_rules: tuple[str, ...]
    container: str
    severity: str


@dataclass(frozen=True)
class Outcome:
    """What actually happened to one file."""

    path: Path
    removed: tuple[str, ...]
    status: str
    detail: str = ""


# --------------------------------------------------------------------------
# planning
# --------------------------------------------------------------------------


def build_plans(report: dict[str, Any], include_review: bool) -> list[Plan]:
    """Turn a scan report into one plan per affected file."""
    wanted = {"secret"} | ({"review"} if include_review else set())
    plans = []
    for entry in report.get("files", []):
        hits = [f for f in entry["findings"] if f["verdict"] in wanted]
        if not hits:
            continue
        containers = {f.get("container", "text") for f in hits}
        plans.append(Plan(
            path=Path(entry["path"]),
            doomed_rules=tuple(sorted({f["rule_string"] for f in hits})),
            container="json" if containers == {"json"} else "text",
            severity=entry["severity"],
        ))
    return plans


def suggest_replacement(rule: str) -> str:
    """A safer rule the user could add back by hand, if they want to.

    Deliberately only a suggestion: any pattern broad enough to cover the
    original command is broader than the original command.
    """
    inner = rule[5:-1] if rule.startswith("Bash(") and rule.endswith(")") else rule
    head = inner.split()[0] if inner.split() else inner
    if "=" in head:                       # e.g. PGPASSWORD=xxx -> env-var form
        var = head.split("=", 1)[0]
        rest = " ".join(inner.split()[1:2])
        return f'Bash({var}="$MY_SECRET" {rest}:*)  # export MY_SECRET first'
    return f"Bash({head}:*)"


# --------------------------------------------------------------------------
# editing
# --------------------------------------------------------------------------


def classify(path: Path) -> str:
    """'credential-store' (never edit) or 'approval-record' (safe to prune)."""
    return "credential-store" if path.name in CREDENTIAL_STORE_NAMES else "approval-record"


def digest(path: Path) -> str:
    """SHA-256 of a file, used to prove a credential store was not altered."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def protect_file(path: Path, dry: bool, untrack: bool) -> Outcome:
    """Close the leak path for a live credential file without touching it.

    The file's contents are never read into the fix and never rewritten; the
    digest is compared before and after to prove it. Three cases:

      outside a repo  - git cannot leak it; nothing to do
      untracked       - add a repo-local ignore rule (zero functional risk)
      tracked         - additionally needs `git rm --cached`, which changes
                        the git index, so it requires an explicit --untrack
    """
    before = digest(path)
    repo = repo_root(path)
    if repo is None:
        return Outcome(path, (), "safe-from-git",
                       "not inside a repository - git cannot expose it")

    rel = str(path.relative_to(repo))
    tracked = _git_ok(["ls-files", "--error-unmatch", rel], repo)
    notes = [ensure_ignore_entry(repo, rel, dry)]

    if tracked:
        if not untrack:
            notes.append(f"STILL TRACKED - rerun with --untrack to run "
                         f"`git rm --cached {rel}` (file stays on disk)")
        elif dry:
            notes.append(f"would run: git rm --cached {rel}")
        elif _git_ok(["rm", "--cached", "--quiet", rel], repo):
            notes.append("untracked (file kept on disk); commit and push to "
                         "complete - this script never commits")
        else:
            notes.append("git rm --cached failed - left tracked")

    if not dry and digest(path) != before:
        return Outcome(path, (), "error", "file changed unexpectedly - aborted")
    status = "protected" if not dry else "would-protect"
    return Outcome(path, (), status, "; ".join(n for n in notes if n))


def _git_ok(args: Sequence[str], cwd: Path) -> bool:
    try:
        return subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=20,
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def ensure_ignore_entry(repo: Path, rel: str, dry: bool) -> str:
    """Add one repo-local ignore rule, so it travels to clones and forks."""
    target = repo / ".gitignore"
    existing = target.read_text(encoding="utf-8") if target.exists() else ""
    if rel in existing.splitlines():
        return "already in repo .gitignore"
    if dry:
        return f"would add '{rel}' to {repo.name}/.gitignore"
    prefix = "" if not existing or existing.endswith("\n") else "\n"
    target.write_text(
        existing + prefix
        + f"\n# Holds credentials - keep local\n{rel}\n",
        encoding="utf-8",
    )
    return f"added '{rel}' to {repo.name}/.gitignore"


def backup(path: Path) -> Path:
    """Owner-only copy kept OUTSIDE any repository.

    A backup of a file full of credentials is itself a file full of
    credentials. Putting it next to the original would just create a new
    committable copy, so it goes to a private cache directory instead.
    """
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.chmod(0o700)
    flat = str(path.resolve()).lstrip("/").replace("/", "_")
    dest = BACKUP_DIR / f"{flat}.{time.strftime('%Y%m%d-%H%M%S')}.bak"
    shutil.copy2(path, dest)
    dest.chmod(0o600)
    return dest


def strip_rules(document: Any, doomed: Sequence[str]) -> tuple[Any, list[str]]:
    """Return a new document with doomed permission rules removed.

    Pure: the input document is not mutated.
    """
    removed: list[str] = []
    doomed_set = set(doomed)
    permissions = document.get("permissions")
    if not isinstance(permissions, dict):
        return document, removed

    new_permissions = dict(permissions)
    for key in RULE_LISTS:
        rules = permissions.get(key)
        if not isinstance(rules, list):
            continue
        kept = [r for r in rules if r not in doomed_set]
        removed.extend(r for r in rules if r in doomed_set)
        new_permissions[key] = kept
    return {**document, "permissions": new_permissions}, removed


def verify(original: Any, updated: Any, removed: Sequence[str]) -> str | None:
    """Confirm the edit changed exactly what it was supposed to.

    Returns an error string, or None when the file is safe to keep.
    """
    if set(original.keys()) != set(updated.keys()):
        return "top-level keys changed"
    old_perms = original.get("permissions") or {}
    new_perms = updated.get("permissions") or {}
    if set(old_perms.keys()) != set(new_perms.keys()):
        return "permissions keys changed"
    for key in RULE_LISTS:
        before = old_perms.get(key) or []
        after = new_perms.get(key) or []
        lost = [r for r in before if r not in after]
        if any(r not in removed for r in lost):
            return f"unintended rule removed from '{key}'"
        if any(r not in before for r in after):
            return f"unexpected rule added to '{key}'"
    for key, value in original.items():
        if key != "permissions" and updated.get(key) != value:
            return f"unrelated setting '{key}' was modified"
    return None


def apply_to_json(path: Path, doomed: Sequence[str], dry: bool) -> Outcome:
    """Remove doomed rules from one settings file, with rollback on doubt."""
    try:
        original = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return Outcome(path, (), "error", f"cannot parse: {exc}")

    updated, removed = strip_rules(original, doomed)
    if not removed:
        return Outcome(path, (), "skipped", "no matching permission rules")
    if dry:
        return Outcome(path, tuple(removed), "would-remove")

    problem = verify(original, updated, removed)
    if problem:
        return Outcome(path, (), "error", f"refused: {problem}")

    saved = backup(path)
    path.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")

    reread = _reread(path)
    if reread is None or verify(original, reread, removed) is not None:
        shutil.copy2(saved, path)
        return Outcome(path, (), "rolled-back", "post-write check failed")
    return Outcome(path, tuple(removed), "cleaned", f"backup: {saved}")


def _reread(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


# --------------------------------------------------------------------------
# repo hygiene
# --------------------------------------------------------------------------


def repo_root(path: Path) -> Path | None:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=path.parent, capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return Path(proc.stdout.strip()) if proc.returncode == 0 else None


def ensure_gitignore(repo: Path, dry: bool) -> str:
    """Add a travelling ignore rule to the repo's own .gitignore."""
    target = repo / ".gitignore"
    existing = target.read_text(encoding="utf-8") if target.exists() else ""
    missing = [e for e in GITIGNORE_ENTRIES if e not in existing.splitlines()]
    if not missing:
        return "already covered by repo .gitignore"
    if dry:
        return f"would add to .gitignore: {', '.join(missing)}"
    block = "\n# Agent approval files - may contain credentials\n" + "\n".join(missing) + "\n"
    prefix = "" if existing.endswith("\n") or not existing else "\n"
    target.write_text(existing + prefix + block, encoding="utf-8")
    return f"added to .gitignore: {', '.join(missing)}"


# --------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------


def report_outcome(outcome: Outcome) -> None:
    print(f"  [{outcome.status}] {outcome.path}")
    if outcome.detail:
        print(f"      {outcome.detail}")
    for rule in outcome.removed:
        flat = " ".join(rule.split())
        shown = flat if len(flat) <= 140 else flat[:137] + "..."
        print(f"      - removed: {shown}")
        print(f"        if you still need it: {suggest_replacement(rule)}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", help="JSON report produced by scan.py")
    parser.add_argument("--apply", action="store_true", help="write changes")
    parser.add_argument("--include-review", action="store_true")
    parser.add_argument("--gitignore", action="store_true",
                        help="also add a travelling ignore rule to each repo")
    parser.add_argument("--untrack", action="store_true",
                        help="for already-tracked credential files, run "
                             "`git rm --cached` (keeps the file on disk; "
                             "never commits or pushes)")
    args = parser.parse_args(argv)

    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    plans = build_plans(report, args.include_review)
    dry = not args.apply

    if not plans:
        print("  Nothing to remediate.")
        return 0

    print(f"\n  {'PREVIEW (no changes written)' if dry else 'APPLYING CHANGES'}\n")
    manual: list[Plan] = []
    for plan in plans:
        if not plan.path.exists():
            continue
        if classify(plan.path) == "credential-store":
            # Live wiring: protect it, never edit it.
            report_outcome(protect_file(plan.path, dry, args.untrack))
            print()
            continue
        if plan.container != "json":
            manual.append(plan)
            continue
        report_outcome(apply_to_json(plan.path, plan.doomed_rules, dry))
        if args.gitignore:
            root = repo_root(plan.path)
            if root:
                print(f"      {ensure_gitignore(root, dry)}")
        print()

    if manual:
        print("  Needs a human - prose and notes are not auto-edited:")
        for plan in manual:
            print(f"    {plan.path} ({len(plan.doomed_rules)} line(s))")
        print()

    print("  Nothing here changes how the agent behaves:")
    print("    - approval records: a removed rule just means Claude asks")
    print("      permission again next time, which is normal behaviour.")
    print("    - credential stores: not edited at all, only hidden from git.")
    print("      Every MCP server keeps the exact values it has now.")
    print("    Verify with: claude mcp list   (expect no warnings)\n")
    if dry:
        print("  Re-run with --apply to write these changes.\n")
    else:
        print("  NOW ROTATE every credential listed above. Removal does not")
        print("  undo exposure - git history, forks and clones still have it.")
        print("  Backups still hold the old secrets in cleartext:")
        print(f"    {BACKUP_DIR}")
        print("  Delete them once you have confirmed everything still works.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
