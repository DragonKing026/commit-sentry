"""Atheris fuzz target: parse_commit_output() on arbitrary `git commit` output (untrusted tool output)."""
import sys
from pathlib import Path

import atheris

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "hooks"))
with atheris.instrument_imports():
    import commit_sentry

# parse_commit_output() must accept any string; no exception is expected.
EXPECTED: tuple[type[BaseException], ...] = ()


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(len(data))
    try:
        sha = commit_sentry.parse_commit_output(text)
    except EXPECTED:
        return
    if sha is not None:
        if not isinstance(sha, str) or not 7 <= len(sha) <= 40 or sha.strip("0123456789abcdef"):
            raise AssertionError(f"not a short sha: {sha!r}")
        if sha not in text:
            raise AssertionError("sha not taken from the input")


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
