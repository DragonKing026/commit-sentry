#!/usr/bin/env python3
"""commit-sentry: background two-stage security review of agent commits.

Runs as a PostToolUse hook after `git commit` (see hooks/hooks.json).
Python 3.11+, standard library only. Logic is added in later commits.
"""
from __future__ import annotations

import fcntl
import fnmatch
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

DOCS_ONLY = ["*.md", "*.txt", "*.rst", "CHANGELOG*", "changelog.md"]
ALWAYS_REVIEW = [
    "SKILL.md", "CLAUDE.md", "AGENTS.md", "*/agents/*", "agents/*", "*/rules/*", "rules/*",
    ".claude/*", "*/hooks/*", "hooks/*", ".claude-plugin/*", "*/.claude-plugin/*",
    "*/.claude/*", "commands/*", "*/commands/*",
    "requirements*.txt", "constraints*.txt", "CMakeLists.txt", ".mcp.json", "*/.mcp.json",
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


_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_SKIP_TOKENS = {"(", ")", "{", "}", "!"}
_GIT_VALUE_OPTS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env"}


def _newlines_to_semicolons(command: str) -> str:
    """Replace unquoted newlines with ';' (newlines inside quotes are kept)."""
    out: list[str] = []
    quote = ""
    i = 0
    while i < len(command):
        ch = command[i]
        if quote:
            if ch == "\\" and quote == '"' and i + 1 < len(command):
                out.append(ch)
                i += 1
                ch = command[i]
            elif ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == "\\" and i + 1 < len(command):
            out.append(ch)
            i += 1
            ch = command[i]
        elif ch == "\n":
            ch = " ; "
        out.append(ch)
        i += 1
    return "".join(out)


def _segments(command: str) -> list[list[str]]:
    """Split a shell command into simple commands at &&, ||, ;, |, & and unquoted newlines.

    Leading `(`, `{`, `}`, `!` and `NAME=value` tokens are dropped from each segment.
    """
    lex = shlex.shlex(_newlines_to_semicolons(command), posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    try:
        tokens = list(lex)
    except ValueError:
        return []
    segs: list[list[str]] = [[]]
    for tok in tokens:
        if tok and set(tok) <= set("();&|"):
            if set(tok) & set(";&|"):
                segs.append([])
            continue
        segs[-1].append(tok)
    cleaned = []
    for seg in segs:
        while seg and (seg[0] in _SKIP_TOKENS or _ENV_ASSIGN.match(seg[0])):
            seg = seg[1:]
        if seg:
            cleaned.append(seg)
    return cleaned


def _git_subcommand_index(seg: list[str]) -> int | None:
    """Index of the git subcommand in `git [-C dir] [-c k=v] <sub> ...`."""
    if not seg or seg[0] != "git":
        return None
    i = 1
    while i < len(seg) and seg[i].startswith("-"):
        i += 2 if seg[i] in _GIT_VALUE_OPTS else 1
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
    """fnmatch on the path; patterns without '/' match the file name only."""
    base = path.rsplit("/", 1)[-1]
    return any(
        fnmatch.fnmatchcase(path if "/" in pat else base, pat) for pat in patterns
    )


def skip_reason(commit: Commit, rules: Rules) -> str | None:
    """'merge', 'empty', 'docs-only', or None when the commit should be reviewed."""
    if len(commit.parents) > 1:
        return "merge"
    if not commit.files:
        return "empty"
    if all(matches(f, rules.docs_only) and not matches(f, rules.always_review) for f in commit.files):
        return "docs-only"
    return None


def state_dir() -> Path:
    """Directory for rate limit, failure markers and the log (created with mode 0700)."""
    override = os.environ.get("COMMIT_SENTRY_STATE_DIR") or os.environ.get("CLAUDE_PLUGIN_DATA")
    if override:
        d = Path(override)
    else:
        base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
        d = Path(base) / "commit-sentry"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        d.chmod(0o700)
    except OSError:
        pass
    return d


def log_path() -> Path:
    return state_dir() / "reviews.jsonl"


def take_rate_slot(now: float, limit: int, window: int) -> bool:
    """Record a review start if fewer than `limit` happened in the last `window` seconds."""
    d = state_dir()
    with open(d / "rate.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = d / "rate.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            stamps = [float(t) for t in data if isinstance(t, (int, float))]
        except (OSError, ValueError, TypeError):
            stamps = []
        stamps = [t for t in stamps if now - t < window]
        ok = len(stamps) < limit
        if ok:
            stamps.append(now)
        tmp = d / f"rate.json.{os.getpid()}.tmp"
        tmp.write_text(json.dumps(stamps), encoding="utf-8")
        os.replace(tmp, path)
        return ok


def first_failure(session_id: str) -> bool:
    """True only the first time it is called for this session (race-safe marker file)."""
    name = "failed-" + hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:16]
    try:
        fd = os.open(state_dir() / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return False
    os.close(fd)
    return True


def append_log(record: dict) -> None:
    """Append one JSON line to reviews.jsonl, adding `ts` unless provided."""
    rec = dict(record)
    rec.setdefault("ts", datetime.now(timezone.utc).isoformat(timespec="seconds"))
    line = json.dumps(rec, ensure_ascii=False) + "\n"
    with open(log_path(), "a", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(line)
        f.flush()


def main(argv=None) -> int:
    return 0


if __name__ == "__main__":
    sys.exit(main())
