# agent-secret-sweep

A Claude Code skill that finds credentials your coding agent wrote into its
own config files — and removes them **without breaking anything**.

Built after [Apiiro's research (Nov 2026)](https://apiiro.com/blog/coding-agents-leaking-secrets-github-dont-ask-again)
found **2,539 real secrets in 1,994 public GitHub repositories**, leaked by
agents rather than by people.

---

## The problem

Claude Code asks before running a shell command. Choose **"Yes, and don't ask
again"** and it saves the *literal command string* as a permission rule in
`.claude/settings.local.json`:

```json
"allow": ["Bash(PGPASSWORD=hunter2 psql -h db.prod.example.com -U admin)"]
```

The password had to be in the command for the command to work. Now it is in a
plain JSON file at a predictable path. Four things make that worse:

1. **Approval fatigue** — after the tenth prompt nobody reads the command.
2. **The gitignore gap** — Claude Code adds the file to your *global* ignore
   list, never the repo's own `.gitignore`. That rule does not travel to a
   clone, a fork, or a folder that became a repo later.
3. **Already-tracked files** — if the file is tracked, new approvals are
   appended to it silently.
4. **Scanners miss it** — gitleaks and TruffleHog match key *formats*. A
   password after `PGPASSWORD=`, `sshpass -p` or `mysql -p` is an ordinary
   word in an ordinary command line. In Apiiro's sample, 215 of 1,122 leaking
   files were caught by neither tool.

Deleting the file does not fix it: git history, forks and clones keep it.

## Install

```bash
git clone https://github.com/shahsahil264/agent-secret-sweep
cp -r agent-secret-sweep/skill ~/.claude/skills/agent-secret-sweep
```

Then just ask Claude: *"check my machine for leaked agent secrets"*.

Or run it directly — stdlib-only Python 3.9+, no dependencies:

```bash
python3 ~/.claude/skills/agent-secret-sweep/scripts/scan.py ~/code \
    --json /tmp/sweep.json
python3 ~/.claude/skills/agent-secret-sweep/scripts/remediate.py /tmp/sweep.json
```

`scan.py` never writes. `remediate.py` previews by default and needs
`--apply`. Scan exits non-zero on real findings, so it drops into CI.

## The part most cleanups get wrong

A leaked credential comes in **two shapes that need opposite fixes**:

| Shape | Files | What the secret is | Correct fix |
|---|---|---|---|
| **Approval record** | `.claude/settings.local.json`, `.claude/settings.json` | a *transcript* of a command you approved — nothing authenticates with it | delete the rule |
| **Credential store** | `.mcp.json`, `.cursor/mcp.json`, `~/.claude.json` | *live wiring* — the MCP server authenticates with it at startup | **never edit it** — hide it from git |

Delete a value from a credential store and the server dies. Hide the file
from git and the leak closes while the bytes stay identical, so everything
keeps working. This tool enforces the split by filename and verifies a
credential store's SHA-256 is unchanged before and after.

It also knows that `~/.claude.json` sits outside any repository and therefore
cannot leak through git — it reports that as a local malware-exposure risk
rather than "fixing" something that is not broken.

## What it detects

- **16 provider formats** — AWS, GitHub (classic + fine-grained), GitLab,
  OpenAI, Anthropic, Slack, Stripe, Square, npm, Supabase, Google, Hugging
  Face, JWT/service keys, private key blocks, Slack webhooks
- **9 embedded-credential patterns** that format-based scanners miss —
  `PGPASSWORD=`, `MYSQL_PWD=`, `mysql -p`, `sshpass -p`, `--password=`,
  curl basic auth, bearer/basic headers, URI credentials, assigned secrets

False positives are suppressed: `$VAR` and `${VAR}` indirection, placeholders,
vendor example keys, and credentials pointing only at localhost or RFC1918
addresses (reported as `review`, not `secret`).

## Exposure grading

Severity is exposure × confidence, not confidence alone:

| Severity | Meaning |
|---|---|
| `critical` | tracked or in git history — forks and clones have it |
| `high` | in a repo with no *travelling* ignore rule |
| `medium` | local only — still a ready-made credential list for malware |
| `low` | unconfirmed match |

It distinguishes a **repo-local** `.gitignore` rule (travels to every clone)
from a **global** one (`~/.config/git/ignore`, protects only your machine) and
warns loudly about the latter. People read "gitignored" as "safe". For this
file, it often isn't.

## Safety guarantees

- Scanning never writes
- Remediation previews by default; `--apply` is explicit
- Backups go **outside** every repo, mode 600 — a backup of a credential file
  is a credential file
- Edits are diff-verified and auto-rolled-back if anything unexpected changed
- Permissions are never broadened; safer wildcard patterns are *suggested*,
  never applied
- Never commits, never pushes, never rotates
- Prose files (`CLAUDE.md`, `MEMORY.md`, handoff notes) are reported, never
  auto-edited
- Secrets are masked in all output

## Prevention

1. Keep secrets out of command lines: `PGPASSWORD="$DB_PASS" psql …` so the
   saved rule records `$DB_PASS`
2. Approve families, not literals: `Bash(npm run:*)`
3. Put `.claude/settings.local.json` in the repo's own `.gitignore`, and in
   your org's gitignore templates
4. Treat `.claude/`, `.cursor/`, `.gemini/` and agent memory files as
   secret-bearing, like `.env`
5. Add the scan to pre-commit or CI

If you do move MCP credentials to `${VAR}` references, know the trap: Claude
Code **blanks credential-named variables** (names containing `TOKEN`,
`SECRET`, `PASSWORD`, `KEY`, `AUTH`) in a remote server's `url` and `headers`,
silently sending an empty value. Use a neutral name, or `headersHelper`.
Verify with `claude mcp list`.

## License

Apache-2.0
