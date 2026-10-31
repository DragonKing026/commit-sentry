#!/usr/bin/env python3
"""Test double for the `claude` CLI (used through COMMIT_SENTRY_CLAUDE).

Environment:
  FAKE_CLAUDE_REPLY   file whose content is printed to stdout; several files separated by
                      os.pathsep are used one per call (the last one repeats)
  FAKE_CLAUDE_RECORD  file that receives {"argv", "stdin", "cwd", "active"} as JSON, one line per call
  FAKE_CLAUDE_EXIT    exit code (default 0)
  FAKE_CLAUDE_SLEEP   seconds to sleep before replying
"""
import json
import os
import sys
import time


def main() -> int:
    stdin = sys.stdin.read()
    record = os.environ.get("FAKE_CLAUDE_RECORD")
    calls = 0
    if record:
        try:
            with open(record, encoding="utf-8") as fh:
                calls = sum(1 for _ in fh)
        except OSError:
            calls = 0
        with open(record, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "argv": sys.argv[1:], "stdin": stdin, "cwd": os.getcwd(),
                "active": os.environ.get("COMMIT_SENTRY_ACTIVE"),
            }) + "\n")
    delay = float(os.environ.get("FAKE_CLAUDE_SLEEP") or 0)
    if delay:
        time.sleep(delay)
    replies = [p for p in (os.environ.get("FAKE_CLAUDE_REPLY") or "").split(os.pathsep) if p]
    if replies:
        with open(replies[min(calls, len(replies) - 1)], encoding="utf-8") as fh:
            sys.stdout.write(fh.read())
    return int(os.environ.get("FAKE_CLAUDE_EXIT") or 0)


if __name__ == "__main__":
    sys.exit(main())
