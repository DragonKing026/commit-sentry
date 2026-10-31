#!/usr/bin/env python3
"""commit-sentry: background two-stage security review of agent commits.

Runs as a PostToolUse hook after `git commit` (see hooks/hooks.json).
Python 3.11+, standard library only. Logic is added in later commits.
"""
from __future__ import annotations

import fnmatch
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field

DOCS_ONLY = ["*.md", "*.txt", "*.rst", "TODO/*", "CHANGELOG*", "changelog.md"]
ALWAYS_REVIEW = [
    "SKILL.md", "CLAUDE.md", "AGENTS.md", "*/agents/*", "agents/*", "*/rules/*", "rules/*",
    ".claude/*", "*/hooks/*", "hooks/*", ".claude-plugin/*", "*/.claude-plugin/*",
]
DENY_READ = [".env*", "*.pem", "*.key", "id_rsa*", "id_ed25519*", "Sensitive-data/*", "*/Sensitive-data/*"]
RULES_FILE = os.path.join(".claude", "commit-sentry.md")

_COMMIT_LINE = re.compile(r"^\[[^\]]* ([0-9a-f]{7,40})\]", re.MULTILINE)
_SEPARATORS = {"&&", ";", "||", "|", "&", ";;"}


@dataclass
class Commit:
    sha: str
    parents: list[str]
    files: list[str]


@dataclass
class Rules:
    text: str = ""
    docs_only: list[str] = field(default_factory=lambda: list(DOCS_ONLY))
    always_review: list[str] = field(default_factory=lambda: list(ALWAYS_REVIEW))
    deny_read: list[str] = field(default_factory=lambda: list(DENY_READ))


def _git(repo: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", repo, *args], check=False, capture_output=True, text=True)


def parse_commit_output(text: str) -> str | None:
    """Short sha from the `[branch sha] subject` line of `git commit` output."""
    m = _COMMIT_LINE.search(text or "")
    return m.group(1) if m else None


def _segments(command: str) -> list[list[str]]:
    """Split a shell command into simple commands at &&, ||, ;, | and &."""
    lex = shlex.shlex(command, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    try:
        tokens = list(lex)
    except ValueError:
        return []
    segs: list[list[str]] = [[]]
    for tok in tokens:
        if tok in _SEPARATORS:
            segs.append([])
        else:
            segs[-1].append(tok)
    return [s for s in segs if s]


def _git_subcommand_index(seg: list[str]) -> int | None:
    """Index of the git subcommand in `git [-C dir] [-c k=v] <sub> ...`."""
    if not seg or seg[0] != "git":
        return None
    i = 1
    while i < len(seg) and seg[i].startswith("-"):
        i += 2 if seg[i] in ("-C", "-c") else 1
    return i if i < len(seg) else None


def _git_C_dir(seg: list[str]) -> str | None:
    """Last directory given with `git -C <dir>` before the subcommand."""
    idx = _git_subcommand_index(seg)
    if idx is None:
        return None
    d = None
    for i in range(1, idx):
        if seg[i] == "-C" and i + 1 < idx:
            d = seg[i + 1]
    return d


def _is_git_commit(seg: list[str]) -> bool:
    idx = _git_subcommand_index(seg)
    return idx is not None and seg[idx] == "commit"


def target_repo(command: str, cwd: str) -> str:
    """Repository a `git commit` command acts on (cd / git -C aware), else the session cwd."""
    cur = cwd
    for seg in _segments(command):
        if seg[0] == "cd" and len(seg) > 1:
            cur = os.path.normpath(os.path.join(cur, os.path.expanduser(seg[1])))
        elif _is_git_commit(seg):
            c = _git_C_dir(seg)
            if c:
                cur = os.path.normpath(os.path.join(cur, os.path.expanduser(c)))
            break
    r = _git(cur, "rev-parse", "--show-toplevel")
    top = r.stdout.strip()
    return top if r.returncode == 0 and top else cur


def resolve_commit(repo: str, short: str) -> Commit | None:
    """Full sha, parents and changed files of a commit; None if it does not exist."""
    r = _git(repo, "rev-parse", "--verify", "--quiet", f"{short}^{{commit}}")
    sha = r.stdout.strip()
    if r.returncode != 0 or not sha:
        return None
    parents = _git(repo, "rev-list", "--parents", "-n", "1", sha).stdout.split()[1:]
    out = _git(repo, "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", "-z", sha).stdout
    return Commit(sha=sha, parents=parents, files=[f for f in out.split("\0") if f])


def _split_list(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def load_rules(repo: str) -> Rules:
    """Defaults plus project rules from .claude/commit-sentry.md (header lists are appended)."""
    rules = Rules()
    try:
        with open(os.path.join(repo, RULES_FILE), encoding="utf-8") as fh:
            raw = fh.read()
    except OSError:
        return rules
    lines = raw.split("\n")
    if lines and lines[0].strip() == "---":
        for end in range(1, len(lines)):
            if lines[end].strip() == "---":
                keys = {"docs-only": rules.docs_only, "always-review": rules.always_review,
                        "deny-read": rules.deny_read}
                for line in lines[1:end]:
                    key, _, val = line.partition(":")
                    if key.strip() in keys:
                        keys[key.strip()].extend(_split_list(val))
                raw = "\n".join(lines[end + 1:])
                break
    rules.text = raw
    return rules


def matches(path: str, patterns: list[str]) -> bool:
    """fnmatch on the path; patterns without '/' are also tried on the file name."""
    base = path.rsplit("/", 1)[-1]
    for pat in patterns:
        if fnmatch.fnmatchcase(path, pat):
            return True
        if "/" not in pat and fnmatch.fnmatchcase(base, pat):
            return True
    return False


def skip_reason(commit: Commit, rules: Rules) -> str | None:
    """'merge', 'empty', 'docs-only', or None when the commit should be reviewed."""
    if len(commit.parents) > 1:
        return "merge"
    if not commit.files:
        return "empty"
    if all(matches(f, rules.docs_only) and not matches(f, rules.always_review) for f in commit.files):
        return "docs-only"
    return None


def main(argv=None) -> int:
    return 0


if __name__ == "__main__":
    sys.exit(main())
