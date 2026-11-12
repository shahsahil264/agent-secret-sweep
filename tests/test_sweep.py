"""Regression suite for agent-secret-sweep.

Three things must never break:
  1. Detection accuracy  - real secrets found, benign strings left alone
  2. Non-destructiveness - unrelated settings survive every edit
  3. Hostile input       - malformed files degrade, never crash
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

SKILL = Path(__file__).resolve().parent.parent / "skills" / "agent-secret-sweep"
sys.path.insert(0, str(SKILL / "scripts"))

from patterns import is_placeholder, mask, public_hosts, scan_text  # noqa: E402
from remediate import (  # noqa: E402
    apply_to_json, backup, classify, ensure_ignore_entry, protect_file,
    strip_rules, suggest_replacement, verify,
)
from scan import (  # noqa: E402
    FileReport, GitFacts, build_report, discover, grade, iter_json_strings,
    print_summary, scan_file,
)
import scan as scan_mod  # noqa: E402

REAL_SECRETS = [
    "PGPASSWORD=Qx9!mLp2zK psql -h db.prod.example.io -U admin",
    "sshpass -p Zz9!qqW3x ssh root@198.51.100.4",
    "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
    "postgresql://svc:Pw9x!2Lm@db.acme.io:5432/app",
    "curl -H 'Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz012345'",
    "AKIAZ3QW7TRBN2PLUXKD",
    "MYSQL_PWD=R8!kdowq mysql -h mysql.acme.io",
]

BENIGN = [
    "Bash(npm run build)",
    "Bash(git status)",
    'Bash(PGPASSWORD=$DB_PASS psql -h db.acme.io -U admin)',
    "Bash(echo $AWS_SECRET_ACCESS_KEY)",
    "Bash(kubectl get pods -n chaos)",
    "password=changeme",
    "api_key: your-key-here",
    'token = "${GITHUB_TOKEN}"',
    "export KEY=<your-key>",
    "Bash(docker compose up -d)",
    "Bash(gh pr list --limit 10)",
    "AKIAIOSFODNN7EXAMPLE",
]


@pytest.mark.unit
@pytest.mark.parametrize("text", REAL_SECRETS)
def test_real_secrets_are_detected(text: str) -> None:
    assert any(f["verdict"] == "secret" for f in scan_text(text, "t")), text


@pytest.mark.unit
@pytest.mark.parametrize("text", BENIGN)
def test_benign_strings_are_not_flagged(text: str) -> None:
    flagged = [f for f in scan_text(text, "t") if f["verdict"] == "secret"]
    assert not flagged, f"false positive on {text!r}: {flagged}"


@pytest.mark.unit
def test_private_host_downgrades_to_review() -> None:
    """A credential aimed only at localhost is reported, not called a secret."""
    out = scan_text("PGPASSWORD=localpw123 psql -h localhost -U postgres", "t")
    assert out and all(f["verdict"] == "review" for f in out)


@pytest.mark.unit
def test_secret_value_never_appears_in_output() -> None:
    secret = "Tr0ub4dor83xQ"
    for finding in scan_text(f"PGPASSWORD={secret} psql -h db.acme.io", "t"):
        assert secret not in finding["excerpt"]
        assert secret not in finding["masked"]


@pytest.mark.unit
@pytest.mark.parametrize("value,expected", [
    ("$DB_PASS", True), ("${DB_PASS}", True), ("changeme", True),
    ("your-key-here", True), ("********", True), ("short", True),
    ("Qx9!mLp2zK", False),
])
def test_placeholder_detection(value: str, expected: bool) -> None:
    assert is_placeholder(value) is expected


@pytest.mark.unit
def test_public_hosts_excludes_private_ranges() -> None:
    assert public_hosts("-h db.acme.io") == ("db.acme.io",)
    for private in ("-h localhost", "-h 127.0.0.1", "-h 10.0.0.5",
                    "-h 192.168.1.9", "-h foo.internal"):
        assert public_hosts(private) == ()


@pytest.mark.unit
def test_mask_preserves_nothing_sensitive() -> None:
    assert mask("abcdefghij") == "abc*****ij"
    assert mask("abc") == "***"


# --- non-destructiveness ---------------------------------------------------

@pytest.mark.unit
def test_strip_rules_removes_only_the_target() -> None:
    doc = {
        "permissions": {"allow": ["keep-1", "DOOMED", "keep-2"], "deny": ["d"]},
        "env": {"KEEP": "me"},
        "mcpServers": {"gh": {"env": {"TOKEN": "ghp_x"}}},
    }
    updated, removed = strip_rules(doc, ["DOOMED"])
    assert removed == ["DOOMED"]
    assert updated["permissions"]["allow"] == ["keep-1", "keep-2"]
    assert updated["permissions"]["deny"] == ["d"]
    assert updated["env"] == {"KEEP": "me"}
    assert updated["mcpServers"] == doc["mcpServers"]
    assert verify(doc, updated, removed) is None


@pytest.mark.unit
def test_strip_rules_does_not_mutate_input() -> None:
    doc = {"permissions": {"allow": ["a", "DOOMED"]}}
    strip_rules(doc, ["DOOMED"])
    assert doc["permissions"]["allow"] == ["a", "DOOMED"]


@pytest.mark.unit
@pytest.mark.parametrize("bad_update,reason", [
    ({"permissions": {"allow": []}, "env": {"KEEP": "me"}}, "extra removal"),
    ({"permissions": {"allow": ["a", "evil"]}, "env": {"KEEP": "me"}}, "injection"),
    ({"permissions": {"allow": ["a"]}, "env": {}}, "unrelated setting"),
])
def test_verify_rejects_bad_edits(bad_update: dict, reason: str) -> None:
    original = {"permissions": {"allow": ["a", "S"]}, "env": {"KEEP": "me"}}
    assert verify(original, bad_update, ["S"]) is not None, reason


@pytest.mark.unit
@pytest.mark.parametrize("name,expected", [
    (".mcp.json", "credential-store"),
    ("mcp.json", "credential-store"),
    (".claude.json", "credential-store"),
    ("settings.local.json", "approval-record"),
    ("settings.json", "approval-record"),
])
def test_classification_decides_which_fix_applies(name: str, expected: str) -> None:
    assert classify(Path("/x") / name) == expected


# --- hostile input ---------------------------------------------------------

@pytest.mark.unit
@pytest.mark.parametrize("doc", [
    {},
    {"env": {"A": "1"}},
    {"permissions": "not-a-dict"},
    {"permissions": {"allow": "not-a-list"}},
    {"permissions": {"allow": [1, None, {"a": 1}, ["x"]]}},
    {"permissions": {"allow": []}},
])
def test_strip_rules_survives_malformed_documents(doc: dict) -> None:
    updated, removed = strip_rules(doc, ["anything"])
    assert removed == []
    assert isinstance(updated, dict)


@pytest.mark.unit
@pytest.mark.parametrize("text", [
    "", "A" * 10_000, "PGPASSWORD=пароль123 psql -h db.acme.io 🔑",
    "tok\x00en=abcdefgh", "password=((((*+?[", "\n\n\t  ",
])
def test_scanner_survives_hostile_text(text: str) -> None:
    assert isinstance(scan_text(text, "t"), list)


@pytest.mark.integration
def test_scan_cli_handles_broken_files(tmp_path: Path) -> None:
    """A malformed or empty config must not crash the scan."""
    (tmp_path / "p" / ".claude").mkdir(parents=True)
    (tmp_path / "p" / ".claude" / "settings.local.json").write_text("{not json,,,")
    (tmp_path / "p" / ".mcp.json").write_text("")
    proc = subprocess.run(
        [sys.executable, str(SKILL / "scripts" / "scan.py"), str(tmp_path), "--depth", "4"],
        capture_output=True, text=True, timeout=120,
    )
    assert "Traceback" not in proc.stderr
    assert proc.returncode in (0, 1)


@pytest.mark.integration
def test_end_to_end_cleans_secret_and_keeps_everything_else(tmp_path: Path) -> None:
    """The whole point: the secret goes, nothing else moves."""
    proj = tmp_path / "proj" / ".claude"
    proj.mkdir(parents=True)
    settings = proj / "settings.local.json"
    settings.write_text(json.dumps({
        "permissions": {
            "allow": [
                "Bash(npm run build)",
                "Bash(PGPASSWORD=Tr0ub4dor83x psql -h db.acme.io -U admin)",
            ],
            "deny": [],
        },
        "env": {"KEEP": "me"},
    }))
    report = tmp_path / "r.json"
    subprocess.run(
        [sys.executable, str(SKILL / "scripts" / "scan.py"), str(tmp_path),
         "--depth", "4", "--json", str(report)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    subprocess.run(
        [sys.executable, str(SKILL / "scripts" / "remediate.py"), str(report), "--apply"],
        capture_output=True, text=True, timeout=120, check=False,
    )
    result = json.loads(settings.read_text())
    assert "Bash(npm run build)" in result["permissions"]["allow"]
    assert result["env"] == {"KEEP": "me"}
    assert result["permissions"]["deny"] == []
    assert not any("Tr0ub4dor" in r for r in result["permissions"]["allow"])


@pytest.mark.integration
def test_credential_store_is_never_edited(tmp_path: Path) -> None:
    """An .mcp.json must come out byte-identical - servers depend on it."""
    import hashlib

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    mcp = repo / ".mcp.json"
    mcp.write_text(json.dumps({"mcpServers": {"o": {"command": "x", "env": {
        "ES": "https://u:Pw9x2Qz7kk@es.acme.io:443"}}}}))
    before = hashlib.sha256(mcp.read_bytes()).hexdigest()

    report = tmp_path / "r.json"
    subprocess.run(
        [sys.executable, str(SKILL / "scripts" / "scan.py"), str(tmp_path),
         "--depth", "4", "--json", str(report)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    subprocess.run(
        [sys.executable, str(SKILL / "scripts" / "remediate.py"), str(report), "--apply"],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert hashlib.sha256(mcp.read_bytes()).hexdigest() == before
    assert ".mcp.json" in (repo / ".gitignore").read_text()


# --- exposure grading: the riskiest logic in the tool ----------------------

SECRET = [{"verdict": "secret"}]
REVIEW = [{"verdict": "review"}]


@pytest.mark.unit
def test_grade_no_findings_is_none() -> None:
    assert grade(GitFacts(), []) == "none"


@pytest.mark.unit
@pytest.mark.parametrize("git,findings,expected", [
    (GitFacts(repo_root="/r", tracked=True, has_remote=True), SECRET, "critical"),
    (GitFacts(repo_root="/r", in_history=True, has_remote=True), SECRET, "critical"),
    (GitFacts(repo_root="/r", tracked=True), REVIEW, "high"),
    (GitFacts(repo_root="/r"), SECRET, "high"),
    (GitFacts(repo_root="/r"), REVIEW, "medium"),
    (GitFacts(), SECRET, "medium"),
    (GitFacts(), REVIEW, "low"),
])
def test_grade_reflects_real_exposure(git, findings, expected) -> None:
    assert grade(git, findings) == expected


@pytest.mark.unit
def test_global_gitignore_does_not_count_as_protection() -> None:
    """The central trap: a global ignore rule does not travel to clones."""
    global_ignore = GitFacts(
        repo_root="/r", ignored=True,
        ignored_by="/Users/someone/.config/git/ignore",
    )
    repo_ignore = GitFacts(repo_root="/r", ignored=True, ignored_by=".gitignore")
    exclude = GitFacts(repo_root="/r", ignored=True,
                       ignored_by="/r/.git/info/exclude")

    assert global_ignore.ignore_travels is False
    assert exclude.ignore_travels is False
    assert repo_ignore.ignore_travels is True
    # and that distinction must change the severity
    assert grade(global_ignore, SECRET) == "high"
    assert grade(repo_ignore, SECRET) == "medium"


@pytest.mark.unit
def test_iter_json_strings_walks_nested_structures() -> None:
    doc = {"a": "x", "b": {"c": ["y", {"d": "z"}]}, "n": 1, "t": True}
    found = dict(iter_json_strings(doc))
    assert found == {"$.a": "x", "$.b.c[0]": "y", "$.b.c[1].d": "z"}


@pytest.mark.unit
def test_scan_file_falls_back_to_lines_for_broken_json(tmp_path: Path) -> None:
    broken = tmp_path / "settings.json"
    broken.write_text('{ "allow": [ "PGPASSWORD=Qx9mLp2zK psql -h db.acme.io" ,,,')
    findings = scan_file(broken)
    assert any(f["verdict"] == "secret" for f in findings)
    assert all(f["container"] == "text" for f in findings)


@pytest.mark.unit
def test_scan_file_on_missing_file_returns_empty(tmp_path: Path) -> None:
    assert scan_file(tmp_path / "nope.json") == ()


@pytest.mark.unit
def test_discover_finds_targets_and_skips_noise(tmp_path: Path) -> None:
    (tmp_path / "proj" / ".claude").mkdir(parents=True)
    (tmp_path / "proj" / ".claude" / "settings.local.json").write_text("{}")
    (tmp_path / "proj" / "node_modules" / ".claude").mkdir(parents=True)
    (tmp_path / "proj" / "node_modules" / ".claude" / "settings.local.json").write_text("{}")
    found = [str(p) for p in discover([tmp_path], 6)]
    assert any("proj/.claude/settings.local.json" in f for f in found)
    assert not any("node_modules" in f for f in found)


# --- file-touching remediation logic --------------------------------------

def _settings(tmp_path: Path) -> Path:
    path = tmp_path / "settings.local.json"
    path.write_text(json.dumps({
        "permissions": {"allow": ["Bash(ls)", "Bash(PGPASSWORD=Qx9mLp2z psql -h db.acme.io)"]},
        "env": {"KEEP": "me"},
    }))
    return path


@pytest.mark.unit
def test_apply_to_json_dry_run_writes_nothing(tmp_path: Path) -> None:
    path = _settings(tmp_path)
    before = path.read_bytes()
    out = apply_to_json(path, ["Bash(PGPASSWORD=Qx9mLp2z psql -h db.acme.io)"], dry=True)
    assert out.status == "would-remove"
    assert path.read_bytes() == before


@pytest.mark.unit
def test_apply_to_json_removes_and_keeps_the_rest(tmp_path: Path) -> None:
    path = _settings(tmp_path)
    out = apply_to_json(path, ["Bash(PGPASSWORD=Qx9mLp2z psql -h db.acme.io)"], dry=False)
    assert out.status == "cleaned"
    doc = json.loads(path.read_text())
    assert doc["permissions"]["allow"] == ["Bash(ls)"]
    assert doc["env"] == {"KEEP": "me"}


@pytest.mark.unit
def test_apply_to_json_skips_when_rule_absent(tmp_path: Path) -> None:
    out = apply_to_json(_settings(tmp_path), ["Bash(not-present)"], dry=False)
    assert out.status == "skipped"


@pytest.mark.unit
def test_apply_to_json_reports_unparsable_file(tmp_path: Path) -> None:
    path = tmp_path / "settings.local.json"
    path.write_text("{broken,,,")
    assert apply_to_json(path, ["x"], dry=False).status == "error"


@pytest.mark.unit
def test_backup_lands_outside_the_repo_and_is_private(tmp_path: Path) -> None:
    path = _settings(tmp_path)
    saved = backup(path)
    assert tmp_path not in saved.parents, "backup must not sit beside the original"
    assert oct(saved.stat().st_mode)[-3:] == "600"
    assert saved.read_bytes() == path.read_bytes()
    saved.unlink()


@pytest.mark.unit
def test_ensure_ignore_entry_is_idempotent(tmp_path: Path) -> None:
    assert "added" in ensure_ignore_entry(tmp_path, ".mcp.json", dry=False)
    assert ".mcp.json" in (tmp_path / ".gitignore").read_text()
    assert "already" in ensure_ignore_entry(tmp_path, ".mcp.json", dry=False)
    assert (tmp_path / ".gitignore").read_text().count(".mcp.json") == 1


@pytest.mark.unit
def test_protect_file_outside_repo_does_nothing(tmp_path: Path) -> None:
    path = tmp_path / ".mcp.json"
    path.write_text("{}")
    assert protect_file(path, dry=False, untrack=False).status == "safe-from-git"
    assert not (tmp_path / ".gitignore").exists()


@pytest.mark.integration
def test_protect_file_warns_while_still_tracked(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    path = tmp_path / ".mcp.json"
    path.write_text("{}")
    subprocess.run(["git", "add", "-f", ".mcp.json"], cwd=tmp_path, check=True)
    out = protect_file(path, dry=False, untrack=False)
    assert "STILL TRACKED" in out.detail
    assert path.exists(), "the file must never be deleted"


@pytest.mark.unit
@pytest.mark.parametrize("rule,expect", [
    ("Bash(PGPASSWORD=x psql -h db)", "$MY_SECRET"),
    ("Bash(curl -H auth https://x)", "Bash(curl:*)"),
])
def test_suggest_replacement_is_only_a_suggestion(rule: str, expect: str) -> None:
    assert expect in suggest_replacement(rule)


# --- output must never print a live secret --------------------------------

@pytest.mark.unit
def test_summary_masks_secrets(tmp_path: Path, capsys) -> None:
    secret = "Tr0ub4dor83xQ"
    path = tmp_path / ".claude" / "settings.local.json"
    path.parent.mkdir()
    path.write_text(json.dumps({"permissions": {"allow": [
        f"Bash(PGPASSWORD={secret} psql -h db.acme.io -U admin)"]}}))
    reports = build_report([path])
    assert reports, "the fixture should produce a finding"
    print_summary(reports, 1, show_all=True)
    out = capsys.readouterr().out
    assert secret not in out, "a live secret reached stdout"
    assert "SECRET" in out and "db.acme.io" in out


@pytest.mark.unit
def test_summary_handles_no_findings(capsys) -> None:
    print_summary([], 5, show_all=False)
    assert "No credentials found" in capsys.readouterr().out


@pytest.mark.unit
def test_cli_exit_code_signals_real_findings(tmp_path: Path) -> None:
    """Non-zero exit is what makes this usable in CI."""
    clean = tmp_path / "clean" / ".claude"
    clean.mkdir(parents=True)
    (clean / "settings.local.json").write_text('{"permissions":{"allow":["Bash(ls)"]}}')
    assert scan_mod.main([str(tmp_path), "--depth", "4"]) == 0

    dirty = tmp_path / "dirty" / ".claude"
    dirty.mkdir(parents=True)
    (dirty / "settings.local.json").write_text(json.dumps({"permissions": {"allow": [
        "Bash(PGPASSWORD=Qx9mLp2zK psql -h db.acme.io -U admin)"]}}))
    assert scan_mod.main([str(tmp_path), "--depth", "4"]) == 1


@pytest.mark.unit
def test_cli_writes_json_report(tmp_path: Path) -> None:
    conf = tmp_path / "p" / ".claude"
    conf.mkdir(parents=True)
    (conf / "settings.local.json").write_text(json.dumps({"permissions": {"allow": [
        "Bash(sshpass -p Zz9qqW3x ssh root@198.51.100.4)"]}}))
    out = tmp_path / "report.json"
    scan_mod.main([str(tmp_path), "--depth", "4", "--json", str(out)])
    payload = json.loads(out.read_text())
    assert payload["files"] and payload["files"][0]["findings"]
    # The report keeps rules verbatim so remediation can match them, which
    # makes it a credential file. It must at least be owner-only.
    assert oct(out.stat().st_mode)[-3:] == "600", "report must not be world-readable"


@pytest.mark.unit
def test_file_report_severity_matches_grade() -> None:
    report = FileReport(path="/x", git=GitFacts(repo_root="/r", tracked=True),
                        findings=({"verdict": "secret"},))
    assert report.severity == "critical"


# --- only a committed .gitignore actually protects a clone -----------------
# Raised by Christopher Alfonso: a repo can point core.excludesFile at another
# file, so your rule looks active locally but the config is never committed.

@pytest.mark.unit
@pytest.mark.parametrize("ignored_by,travels,why", [
    (".gitignore", True, "committed, honoured by default"),
    ("sub/.gitignore", True, "nested .gitignore is committed too"),
    ("/home/u/.config/git/ignore", False, "global file, per-machine"),
    ("/r/.git/info/exclude", False, "per-clone, never committed"),
    (".gitignore-extra", False, "core.excludesFile config is not committed"),
    ("custom-ignores", False, "same, without a suggestive name"),
])
def test_only_committed_gitignore_counts_as_travelling(
    ignored_by: str, travels: bool, why: str
) -> None:
    git = GitFacts(repo_root="/r", ignored=True, ignored_by=ignored_by)
    assert git.ignore_travels is travels, why
    if not travels:
        assert grade(git, [{"verdict": "secret"}]) == "high", why


@pytest.mark.integration
def test_excludesfile_override_is_not_treated_as_safe(tmp_path: Path) -> None:
    """End-to-end version of the same trap, against real git."""
    from scan import git_facts

    repo = tmp_path / "repo"
    (repo / ".claude").mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    target = repo / ".claude" / "settings.local.json"
    target.write_text("{}")
    (repo / ".gitignore-extra").write_text(".claude/settings.local.json\n")
    subprocess.run(["git", "config", "core.excludesFile", ".gitignore-extra"],
                   cwd=repo, check=True)

    facts = git_facts(target)
    assert facts.ignored is True, "git does consider it ignored locally"
    assert facts.ignore_travels is False, "but the rule would not reach a clone"


@pytest.mark.unit
def test_git_facts_survives_unresolved_paths(tmp_path: Path) -> None:
    """Symlinked roots (macOS /tmp -> /private/tmp) must not crash the scan."""
    from scan import git_facts

    assert git_facts(tmp_path / "nowhere" / "settings.local.json") is not None
