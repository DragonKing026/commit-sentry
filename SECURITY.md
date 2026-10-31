# Security policy

## Supported versions

Only the latest release receives security fixes. Please check that the problem still exists in the latest
release (or on `main`) before reporting it.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub private vulnerability reporting:

<https://github.com/DragonKing026/commit-sentry/security/advisories/new>

(or open the repository's **Security** tab and choose **Report a vulnerability**). Please do not open a public
issue, pull request or discussion for security problems.

Please include:

- the affected version (release tag or commit) and your environment (OS, Python version, Claude Code version);
- a description of the problem and its impact, for example what an attacker controls (commit content, Bash
  command, model output, repository files) and what they gain;
- steps to reproduce or a proof of concept, ideally a minimal repository or the exact hook input;
- any suggested fix or mitigation, and whether and how you would like to be credited.

## What to expect

- An acknowledgement of your report within 7 days.
- Coordinated disclosure: we work on a fix with you and agree on a publication date. By default the details are
  published at the latest 90 days after the report, or earlier once a fixed release is available.
- The vulnerability is published as a GitHub Security Advisory for this repository (with a CVE where
  applicable), crediting you unless you prefer otherwise.
