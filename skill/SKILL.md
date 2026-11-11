---
name: agent-secret-sweep
description: Use when checking for, or cleaning up, credentials that coding agents have written into their own config and memory files - especially .claude/settings.local.json permission allowlists created by "Yes, and don't ask again". Triggers - "did I leak a secret", "check my .claude settings", "secrets in settings.local.json", "agent secret scan", "don't ask again leak", "audit agent config for credentials".
---

# Agent Secret Sweep

Find and remove credentials that coding agents persisted into files you may
commit, then leave the agent working exactly as it did before.

## The problem this solves

Claude Code asks before running a shell command. Choosing **"Yes, and don't
ask again"** saves the *literal command string* as a permission rule in
`.claude/settings.local.json`:

```json
"allow": ["Bash(PGPASSWORD=hunter2 psql -h db.prod.example.com -U admin)"]
```

The secret had to be in the command for the command to work, so now it is in
a plain JSON file at a predictable path. Four things make that worse:

1. **Approval fatigue** - after the tenth prompt nobody reads the command.
2. **The gitignore gap** - Claude Code adds the file to your *global* ignore
   list, never the repo's own `.gitignore`. That rule does not travel to a
   clone, a fork, or a folder that became a repo later.
3. **Already-tracked files** - if the file is tracked, new approvals are
   appended to it silently.
4. **Scanners miss it** - gitleaks and TruffleHog match key *formats*. A
   password after `PGPASSWORD=`, `sshpass -p` or `mysql -p` is an ordinary
   word in an ordinary command line.

Apiiro found 2,539 real secrets in 1,994 public repos this way (Nov 2026).
Deleting the file does not help: git history, forks and clones keep it.

## Guarantees

Follow this skill and the agent keeps working normally afterwards:

- **Scanning never writes.** `scan.py` only reads.
- **Only secret-bearing rules are removed.** Every other permission rule,
  env var and setting is preserved, verified by a diff after the write.
- **Permissions are never broadened.** Replacing `Bash(PGPASSWORD=x psql ...)`
  with `Bash(psql:*)` would grant *more* than before, so the tool only
  *suggests* such patterns - it never applies them.
- **Removing an approval does not break anything.** The next time that
  command comes up, Claude asks for permission again. That is normal
  behaviour, not a regression.
- **Backups go outside the repo** (`~/.cache/agent-secret-sweep/backups/`,
  mode 600), because a backup of a credential file is a credential file.
- **Nothing is committed, pushed, or rotated for you.**

## Workflow

### 1. Scan (read-only)

```bash
python3 scripts/scan.py ~/code --depth 6 --json /tmp/sweep.json
```

Give it the directories that hold your projects. `--all` also prints
lower-confidence `review` hits. Exit code is 1 when anything critical or
high is found, so it works in CI.

### 2. Read the severities out loud to the user

| Severity | Meaning | What it demands |
|---|---|---|
| `critical` | tracked or in git history | **rotate now** - forks and clones have it |
| `high` | in a repo, no *travelling* ignore rule | clean + fix `.gitignore` |
| `medium` | local only | clean - malware harvests these files |
| `low` | unconfirmed match | eyeball it |

When a file is ignored only by the user's global ignore file, say so
explicitly. People read "gitignored" as "safe", and for this file it is not.

### 3. Know which of the two fixes applies

A leaked credential comes in two shapes that need **opposite** fixes. Getting
this wrong is how a cleanup breaks someone's agent.

| Shape | Files | What the secret is | Fix |
|---|---|---|---|
| **Approval record** | `.claude/settings.local.json`, `.claude/settings.json` | a *transcript* of a command the user approved - nothing authenticates with it | delete the rule; Claude just asks again |
| **Credential store** | `.mcp.json`, `.cursor/mcp.json`, `~/.claude.json` | *live wiring* - the MCP server authenticates with it at startup | **never edit it**; hide it from git instead |

Deleting a value from a credential store breaks the server. Hiding the file
from git closes the leak while the bytes stay identical, so every server
keeps working. The script enforces this split automatically and compares the
file's SHA-256 before and after to prove a credential store was untouched.

Note: a file in `$HOME` and outside any repo (`~/.claude.json`,
`~/.cursor/mcp.json`) cannot leak through git at all. Report it as a local
malware-exposure risk; do not "fix" it by breaking it.

### 4. Confirm, preview, then apply

Show the masked findings and the exact rules that would go. Preview first:

```bash
python3 scripts/remediate.py /tmp/sweep.json
```

Get the user's agreement, then apply:

```bash
python3 scripts/remediate.py /tmp/sweep.json --apply --gitignore
```

Add `--untrack` to run `git rm --cached` on credential stores that are
already committed. That keeps the file on disk, so nothing stops working.
The script never commits and never pushes - tell the user those two steps
are theirs, and that they are publishing a change to a shared repo.

### 5. Handle what the script will not touch

- **Markdown and notes** (`CLAUDE.md`, `MEMORY.md`, handoff docs) are
  reported, never auto-edited. Edit those yourself, with the user watching.
- **Tracked files.** Offer, do not run unprompted:
  `git rm --cached .claude/settings.local.json`
- **Git history.** Removing the file does not clear it. Say plainly that
  rotation is the only real fix, and mention `git filter-repo` / BFG only as
  a secondary cleanup.

### 6. Verify the agent still works

```bash
python3 -c "import json,sys; json.load(open(sys.argv[1]))" <settings file>
claude mcp list                              # expect: no missing-variable warnings
python3 scripts/scan.py <root> --depth 6     # expect: no findings
```

`claude mcp list` is the real test after touching anything MCP-related: it
reports a missing-variable warning per server when a `${VAR}` cannot be
resolved.

### 7. Why untracking beats rewriting

When a credential-bearing file is reachable by git, the lowest-risk fix is
almost always to stop git seeing it, not to edit it:

```bash
git rm --cached .mcp.json && echo ".mcp.json" >> .gitignore
```

The file stays on disk unchanged, so every server keeps working with the
exact values it has now. Only rewrite values when the file genuinely must be
committed for other people.

If you do rewrite, know the trap: Claude Code **blanks credential-named
variables** (names containing `TOKEN`, `SECRET`, `PASSWORD`, `KEY`, `AUTH`)
in a remote server's `url` and `headers`, silently sending an empty value.
Use a neutral name such as `CHAI_OTA_HEADER`, or use `headersHelper`. An
unset `${VAR}` is passed through literally and usually fails to start the
server. (Source: code.claude.com/docs/en/mcp.md, checked 2026-11-11.)

Then tell the user exactly which approvals disappeared, so the next prompt
for one of those commands is expected rather than alarming.

### 8. Hand over the rotation list

For each confirmed secret: what it is, where it was, how exposed it was, and
that it must be rotated. Never print the secret itself - the report masks it
and so should you.

## Preventing the next one

1. Keep secrets out of command lines: `PGPASSWORD="$DB_PASS" psql ...`, so
   the saved rule records `$DB_PASS`.
2. Approve families, not literals: `Bash(npm run:*)` rather than one exact
   invocation.
3. Put `.claude/settings.local.json` in the repo's own `.gitignore` and in
   your org's gitignore templates.
4. Treat `.claude/`, `.cursor/`, `.gemini/` and agent memory files as
   secret-bearing, like `.env`, on laptops as well as in repos.
5. Add this scan to pre-commit or CI; it exits non-zero on real findings.

## Files

- `scripts/scan.py` - read-only discovery, detection and exposure grading
- `scripts/remediate.py` - preview/apply removal, with rollback and backups
- `scripts/patterns.py` - detection patterns and false-positive suppression

## Source

Apiiro, "Coding Agents Are Leaking Your Secrets to GitHub", 5 Nov 2026.
