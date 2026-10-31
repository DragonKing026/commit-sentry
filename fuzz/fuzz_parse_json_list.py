"""Atheris fuzz target: _parse_json_list() on arbitrary model output (the last ```json block)."""
import sys
from pathlib import Path

import atheris

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "hooks"))
with atheris.instrument_imports():
    import commit_sentry

# json.loads raises RecursionError on very deeply nested arrays; the hook catches it at the top level
# and logs the review as failed (fail-open), so it is not treated as a crash here.
EXPECTED: tuple[type[BaseException], ...] = (RecursionError,)


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(len(data))
    try:
        value = commit_sentry._parse_json_list(text)
    except EXPECTED:
        return
    if value is not None and not isinstance(value, list):
        raise AssertionError(f"expected list or None, got {type(value).__name__}")


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
