# commit-sentry

A Claude Code plugin that reviews every commit your agent makes for security problems, in the background,
and wakes the session only when a finding survives a second, skeptical pass.

## What it does

After each `git commit` run by the agent, commit-sentry starts a headless review of that commit. Stage 1 looks for
vulnerabilities in the diff; stage 2 tries to disprove each finding and discards false positives. Confirmed
HIGH and MEDIUM findings wake the session with a message; LOW findings are only written to the log. The agent
keeps working while the review runs.

## How it works

- A `PostToolUse` hook on `Bash` (filtered to `git*commit*`) runs `hooks/commit_sentry.py` asynchronously
  (`asyncRewake`), so the session is woken only when the script exits with findings.
- The script reads the commit that was just made (in the repository where the commit happened, also for
  `git -C` and worktrees), builds a size-limited diff and runs
  `claude -p --safe-mode --restricted --model opus --tools Read,Grep,Glob --output-format json --no-session-persistence`
  (file tools allowed only inside the repository) twice: find, then verify.
- Failed commits, merge commits and runs started by the reviewer itself are skipped.
- Any internal error is logged and never breaks your session.

## Install

```
/plugin marketplace add DragonKing026/commit-sentry
/plugin install commit-sentry@commit-sentry
```

Requires Python 3.11+ (standard library only), `git`, and the `claude` CLI logged in with your account.

## Configuration

Environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `COMMIT_SENTRY_DISABLE` | unset | `1` turns the plugin off. |
| `COMMIT_SENTRY_ACTIVE` | unset | Set to `1` for child processes to prevent recursion; do not set it yourself. |
| `COMMIT_SENTRY_MODEL` | `opus` | Model used in both stages. |
| `COMMIT_SENTRY_MAX_PER_HOUR` | `20` | Maximum reviews per 3600 s, across all repositories. |
| `COMMIT_SENTRY_STAGE_TIMEOUT` | `300` | Per-stage timeout in seconds (capped at 420; hook limit 900 s). |
| `COMMIT_SENTRY_CLAUDE` | `claude` | Path of the CLI to run (useful for tests). |
| `COMMIT_SENTRY_STATE_DIR` | plugin data dir / `XDG_STATE_HOME` | Overrides where the log and rate-limit state live. |

## Subagents

Observed behaviour, not documented by Claude Code: a commit made by a subagent fires the hook with the same
`session_id` plus an `agent_id`. In a spike (`-p` mode), the exit-2 report reached the context of the
still-running subagent. Interactive behaviour (whether the parent session wakes) is not verified yet. Findings
are always written to the log, whoever receives the report.

## Limits

One Bash command containing several `git commit`s reviews only the first commit.

## Disable

- Everywhere: `COMMIT_SENTRY_DISABLE=1` in the environment of the session.
- Per repository: `git config commit-sentry.enabled false`.

## Manual review

```
python3 hooks/commit_sentry.py --review <sha> [--repo DIR] [--force]
```

Runs the same two stages on any commit and prints the result to stdout (no hourly limit, no session state).
Exit code 0: no confirmed findings (or skipped), 1: confirmed findings, 2: the review failed. Merge commits and
docs-only and empty commits are skipped unless you pass `--force`; `--force` does not override the merge-commit
skip. The run is written to the log with
`session_id` `manual`.

## Project rules file

Put project-specific security rules in `.claude/commit-sentry.md`. Optional front matter adds to the built-in
glob lists (comma-separated, matched with fnmatch; a pattern without `/` matches the file name only):

```
---
docs-only: *.adoc, docs/*
always-review: scripts/*
deny-read: secrets/*.json
---
Free text, added to both review prompts: for example "all SQL goes through the query builder".
```

- `docs-only`: files that do not trigger a review when a commit contains nothing else.
- `always-review`: files that always do, even if they also match `docs-only` (defaults include `SKILL.md`,
  `CLAUDE.md`, `AGENTS.md`, `.claude/*`, hooks, agents, rules, `.mcp.json`).
- `deny-read`: files left out of the diff and denied to the reviewer's file tools (defaults include `.env*`, `*.pem`,
  `*.key`, `id_rsa*`, `Sensitive-data/*`).

## Log

Every review, skip and failure is appended as one JSON line to `reviews.jsonl` in the state directory
(`COMMIT_SENTRY_STATE_DIR`, else `CLAUDE_PLUGIN_DATA`, else `$XDG_STATE_HOME/commit-sentry`, else
`~/.local/state/commit-sentry`; mode 0700). Fields: `ts`, `session_id`, `repo`, `sha`, `files` (count), `outcome`
(`clean`, `findings`, `skipped`, `failed`), `reason`, `stages` (per stage: `name`, `duration_s`, `input_tokens`,
`output_tokens`, `cache_read`, `cache_creation`, `cost_usd`), `cost_usd` (sum), `candidates` (all stage 1
findings, including LOW), `confirmed`, `refuted` (candidates rejected in stage 2, each with the reviewer's
`reason`), `downgraded` (candidates confirmed in stage 2 but rated LOW, each with the reviewer's `reason`;
log only, they do not wake the session), `error`. A commit that cannot be found in the resolved repository
(for example after `cd "$VAR"`) is logged as `skipped` with `reason` `commit-not-found:<sha7>`. The log contains
finding descriptions, so treat it as sensitive.

A manual `--review` run from a terminal has no `CLAUDE_PLUGIN_DATA`, so it writes to
`${XDG_STATE_HOME:-~/.local/state}/commit-sentry/` unless `COMMIT_SENTRY_STATE_DIR` is set: that is a different log
than the hook's. Set `COMMIT_SENTRY_STATE_DIR` to the hook's directory to share one. A relative `XDG_STATE_HOME`
is ignored, as the XDG specification requires.

A failure (no login, quota, timeout, rate limit, internal error) wakes the session once per session with a
one-line notice; later failures in that session are only logged.

## Privacy

The diff of the commit only, not the commit message (size-limited; binary files and files matched by your
`deny-read` permissions are left out),
your `.claude/commit-sentry.md` and whatever files the reviewer reads with `Read`, `Grep` and
`Glob` are sent to the model through the `claude` CLI, under your own account and its data terms. Do not enable the
plugin in repositories whose content must not be sent to Anthropic.

What the reviewer can read: the CLI runs with `--restricted` and
`--allowedTools "Read(./**)" "Grep(./**)" "Glob(./**)"`, which confines its file tools to the repository. Absolute
paths, `../` paths and committed symbolic links that point
outside the repository are refused, and user, project and local settings files are ignored, so a committed
`.claude/settings.json` cannot widen the scope. Inside the repository, files matching `deny-read` and the `.git/`
directory are blocked by deny rules. Residual risk: any other file inside the repository (including untracked files in
the working tree that do not match `deny-read`) can be read and sent to the model, so add patterns for local secrets
to `deny-read`. Admin-managed (policy) settings still apply and could widen the scope.

## Cost

Each review runs up to two Opus sessions and uses your subscription or API quota. The hourly limit
(`COMMIT_SENTRY_MAX_PER_HOUR`) caps the spend. The cost of every stage is recorded in the log (`cost_usd`); stage 2
runs only when stage 1 finds a HIGH or MEDIUM candidate, so most commits cost one session.

## License

Apache-2.0, see [LICENSE](LICENSE). Prompts and hook design are adapted from third-party Apache-2.0 and MIT
projects; see [NOTICE](NOTICE).
