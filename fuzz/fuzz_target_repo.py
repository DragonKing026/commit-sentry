"""Atheris fuzz target: target_repo() command-string parsing (cd / git -C / quoting / separators).

Only the parsing is fuzzed: `git rev-parse` is replaced by a stub that reports "not a repository", so no
process is started and the result is the directory the parser resolved, relative to a temporary cwd.
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import atheris

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "hooks"))
with atheris.instrument_imports():
    import commit_sentry

# os.path.expanduser("~name\0...") raises ValueError (embedded null byte) from the pwd lookup; a real Bash
# command cannot contain NUL, and the hook catches it at the top level, so it is not treated as a crash.
EXPECTED: tuple[type[BaseException], ...] = (ValueError,)

CWD = tempfile.mkdtemp(prefix="cs-fuzz-")


def _no_git(repo: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(["git", "-C", repo, *args], 128, "", "fatal: not a git repository\n")


commit_sentry._git = _no_git


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    command = fdp.ConsumeUnicodeNoSurrogates(len(data))
    try:
        repo = commit_sentry.target_repo(command, CWD)
    except EXPECTED:
        return
    if not isinstance(repo, str) or not repo:
        raise AssertionError(f"expected a path, got {repo!r}")
    if not os.path.isabs(repo):
        raise AssertionError(f"relative path from absolute cwd: {repo!r}")


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
