#!/usr/bin/env python3
"""commit-sentry: background two-stage security review of agent commits.

Runs as a PostToolUse hook after `git commit` (see hooks/hooks.json).
Python 3.11+, standard library only. Logic is added in later commits.
"""
import sys


def main(argv=None) -> int:
    return 0


if __name__ == "__main__":
    sys.exit(main())
