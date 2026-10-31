"""Atheris fuzz target: _parse_json_list() on arbitrary model output (the last ```json block)."""
import sys
from pathlib import Path

import atheris

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "hooks"))
with atheris.instrument_imports():
    import commit_sentry

# _parse_json_list() must accept any string (deep nesting included) and return a list or None.
EXPECTED: tuple[type[BaseException], ...] = ()


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
