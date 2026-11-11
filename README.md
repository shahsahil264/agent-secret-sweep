# agent-secret-sweep

**Your coding agent has been saving your passwords to disk. This finds them
and cleans them up — without breaking anything.**

A Claude Code skill. Zero dependencies, stdlib Python only.

> [Apiiro, Nov 2026](https://apiiro.com/blog/coding-agents-leaking-secrets-github-dont-ask-again):
> **2,539 real secrets in 1,994 public GitHub repositories** — database
> passwords, cloud keys, SSH root logins — leaked by coding agents rather
> than by people. In 539 of those repos, the agent committed the file itself.

---

## 30-second check

Are you affected? Run this right now:

```bash
cat ~/.claude/settings.local.json | grep -iE 'PGPASSWORD|sshpass|password=|bearer |://[^:]+:[^@]+@'
```

Any output is a credential saved on disk by a "don't ask again" click.

## Install

```bash
git clone https://github.com/shahsahil264/agent-secret-sweep
cp -r agent-secret-sweep/skill ~/.claude/skills/agent-secret-sweep
```

Then just ask Claude, in plain English:

> *"check my machine for leaked agent secrets"*

Claude runs the scan, explains what it found and how exposed each item is,
asks before changing anything, and verifies your setup still works.

### Or run it yourself

```bash
# 1. Scan — read-only, never writes
python3 ~/.claude/skills/agent-secret-sweep/scripts/scan.py ~/code \
        --json /tmp/sweep.json

# 2. Preview the fix — still writes nothing
python3 ~/.claude/skills/agent-secret-sweep/scripts/remediate.py /tmp/sweep.json

# 3. Apply it
python3 ~/.claude/skills/agent-secret-sweep/scripts/remediate.py /tmp/sweep.json \
        --apply --gitignore
```

Requires Python 3.9+. Nothing to `pip install`.

## What it looks like

```
  Scanned 175 agent file(s).
  7 file(s) with findings; 14 confirmed secret(s).

  [CRITICAL] /Users/you/project/.mcp.json
      exposure: committed to git - history, forks and clones keep it
                even if you delete the file
      git: tracked,in-history,has-remote  (repo /Users/you/project)
      - SECRET uri-credentials: Bes********t8 -> search-prod.us-east-1.es.amazonaws.com
        at $.mcpServers.orion.env.ES_SERVER: https://svc:Bes********t8@search-prod...

  [HIGH] /Users/you/other/.claude/settings.local.json
      exposure: in a git repo with no .gitignore rule that travels -
                one `git add .`, or one clone on another machine, from exposure
      WARNING: ignored only by /Users/you/.config/git/ignore
               - that rule does NOT travel to clones or forks
      - SECRET sshpass: R00******24 -> 203.0.113.9
```

Secrets are always masked. Exit code is non-zero on real findings, so it
drops straight into CI or a pre-commit hook.

## Will this break my setup?

**No — and that is the central design constraint.**

A leaked credential comes in two shapes that need **opposite** fixes. Most
cleanups know only the first one, and break things with it:

| Shape | Files | What the secret is | Correct fix | Impact |
|---|---|---|---|---|
| **Approval record** | `.claude/settings.local.json`<br>`.claude/settings.json` | a *transcript* of a command you approved — nothing authenticates with it | delete the rule | Claude asks permission once more. That's all |
| **Credential store** | `.mcp.json`<br>`.cursor/mcp.json`<br>`~/.claude.json` | *live wiring* — the MCP server authenticates with it at startup | **never edited** — hidden from git instead | **zero** — bytes unchanged |

Delete a value from a credential store and the server dies. Hide the file
from git and the leak closes while the bytes stay identical. This tool
enforces the split by filename and checks the file's **SHA-256 before and
after** to prove a credential store was untouched.

It also knows `~/.claude.json` lives outside any repository and so cannot
leak through git — it reports that as a local malware risk rather than
"fixing" something that isn't broken.

## Why your existing scanner missed this

gitleaks and TruffleHog match **key formats** — `AKIA…`, `ghp_…`, `sk-…`. A
password sitting inside a shell command is an ordinary word:

```
Bash(PGPASSWORD=Tr0ub4dor83x psql -h db.prod.example.com -U admin)
```

In Apiiro's sample, **215 of 1,122** leaking files were caught by neither
tool. This skill detects both classes:

- **16 provider formats** — AWS, GitHub (classic + fine-grained), GitLab,
  OpenAI, Anthropic, Slack, Stripe, Square, npm, Supabase, Google, Hugging
  Face, JWT/service keys, private key blocks, Slack webhooks
- **9 embedded-credential patterns** — `PGPASSWORD=`, `MYSQL_PWD=`,
  `mysql -p`, `sshpass -p`, `--password=`, curl basic auth, bearer/basic
  headers, URI credentials, assigned secrets

False positives are actively suppressed: `$VAR` / `${VAR}` indirection,
placeholders, vendor example keys, and credentials pointing only at
localhost or RFC1918 addresses (reported as `review`, not `secret`).

## How it grades exposure

Severity is exposure × confidence, not confidence alone:

| Severity | Meaning | Do this |
|---|---|---|
| `critical` | tracked or in git history | **rotate now** — forks and clones have it |
| `high` | in a repo, no *travelling* ignore rule | clean + fix `.gitignore` |
| `medium` | local only | clean — malware harvests these files |
| `low` | unconfirmed match | eyeball it |

**The gitignore trap:** a rule in the repo's own `.gitignore` travels to
every clone and fork. A rule in your *global* ignore file protects only your
machine — a teammate's clone has no such protection. Claude Code writes the
global one. This tool tells the two apart and warns loudly, because people
read "gitignored" as "safe" and here it often isn't.

## Safety guarantees

- Scanning never writes
- Remediation previews by default; `--apply` is explicit
- Backups go **outside** every repo at mode 600 — a backup of a credential
  file is a credential file
- Edits are diff-verified and auto-rolled-back if anything unexpected changed
- Permissions are never broadened; safer wildcard patterns are *suggested*,
  never applied
- Never commits, never pushes, never rotates — those stay human decisions
- Prose files (`CLAUDE.md`, `MEMORY.md`, handoff notes) are reported, never
  auto-edited
- Secrets are masked in every output path

## Use it in CI

```yaml
- name: Check for agent-leaked secrets
  run: |
    python3 skill/scripts/scan.py . --depth 8
    # exits non-zero on critical/high findings
```

## Stop it happening again

1. Keep secrets out of command lines: `PGPASSWORD="$DB_PASS" psql …` so the
   saved rule records `$DB_PASS`, not the password
2. Approve families, not literals: `Bash(npm run:*)` beats one exact command
3. Add `.claude/settings.local.json` to the repo's **own** `.gitignore`, and
   to your org's gitignore templates
4. Treat `.claude/`, `.cursor/`, `.gemini/` and agent memory files as
   secret-bearing, like `.env` — on laptops as well as in repos
5. Wire the scan into pre-commit or CI

**If you move MCP credentials to `${VAR}` references, know the trap:** Claude
Code deliberately **blanks credential-named variables** (names containing
`TOKEN`, `SECRET`, `PASSWORD`, `KEY`, `AUTH`) in a remote server's `url` and
`headers`, silently sending an empty value and getting a 401. Use a neutral
name like `CHAI_API_HEADER`, or use `headersHelper`. Verify with
`claude mcp list`.

## Contributing

New detection patterns are very welcome — especially embedded-credential
shapes for tools not covered yet. Add the pattern to
`skill/scripts/patterns.py` and a true/false-positive case to the regression
set in the README of your PR.

## Credits

Research: [Apiiro](https://apiiro.com/blog/coding-agents-leaking-secrets-github-dont-ask-again),
"Coding Agents Are Leaking Your Secrets to GitHub", 5 November 2026.

## License

Apache-2.0
