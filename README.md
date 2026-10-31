# commit-sentry

A Claude Code plugin that reviews every commit your agent makes for security problems, in the background,
and wakes the session only when a finding survives a second, skeptical pass.

> Status: early draft (0.1.0). The review logic lands in later commits.

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
| `COMMIT_SENTRY_STAGE_TIMEOUT` | `300` | Timeout of each stage in seconds. |
| `COMMIT_SENTRY_CLAUDE` | `claude` | Path of the CLI to run (useful for tests). |
| `COMMIT_SENTRY_STATE_DIR` | plugin data dir / `XDG_STATE_HOME` | Overrides where the log and rate-limit state live. |

Per repository: `git config commit-sentry.enabled false` disables the review there.

## Project rules file

Put project-specific security rules in `.claude/commit-sentry.md` (for example "all SQL goes through the query
builder", "ignore the `fixtures/` directory"). Its content is added to the review prompts. Details TBD in later commits.

## Log

Every review (and every skip or failure) is appended to a log in the state directory. Format and location: TBD in later commits.

## Privacy

The diff of the commit (size-limited; binary files and files matched by your `deny-read` permissions are left out),
the commit message, your `.claude/commit-sentry.md` and whatever files the reviewer reads with `Read`, `Grep` and
`Glob` are sent to the model through the `claude` CLI, under your own account and its data terms. Do not enable the
plugin in repositories whose content must not be sent to Anthropic.

What the reviewer can read: the CLI runs with `--restricted` and
`--allowedTools "Read(./**)" "Grep(./**)" "Glob(./**)"`, which confines its file tools to the repository. Absolute paths, `../` paths and committed symbolic links that point
outside the repository are refused, and user, project and local settings files are ignored, so a committed
`.claude/settings.json` cannot widen the scope. Inside the repository, files matching `deny-read` and the `.git/`
directory are blocked by deny rules. Residual risk: any other file inside the repository (including untracked files in
the working tree that do not match `deny-read`) can be read and sent to the model, so add patterns for local secrets
to `deny-read`. Admin-managed (policy) settings still apply and could widen the scope.

## Cost

Each review runs up to two Opus sessions and uses your subscription or API quota. The hourly limit
(`COMMIT_SENTRY_MAX_PER_HOUR`) caps the spend. Typical numbers: TBD in later commits.

## License

Apache-2.0, see [LICENSE](LICENSE). Prompts and hook design are adapted from third-party Apache-2.0 and MIT
projects; see [NOTICE](NOTICE).
