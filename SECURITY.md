# Security Policy

## Reporting a vulnerability

Found a hole in Git Gud Security itself (the scanner, the patterns, the skill)? Open a
GitHub issue at https://github.com/kidsmeal/git-gud-security/issues. If the issue is
sensitive, mark it as such and keep proof-of-concept details minimal until it's triaged.

There's no bounty and no SLA. This is a solo-maintained tool. Reports are read and acted
on as time allows.

## Scope

In scope:

- The standalone scanner (`scripts/scan.py`) mishandling input, crashing, or leaking the
  contents of a scanned repo somewhere it shouldn't.
- Pattern definitions (`scripts/patterns.json`) that produce a secret in cleartext in
  output that should have been redacted.
- The skill instructions (`SKILL.md`, `references/`) telling Claude to take an unsafe
  action on a scanned repo (honoring its hooks, running its config, executing its code).

Out of scope:

- False positives and false negatives in the checks. Those are accuracy bugs, not
  security bugs. File them as normal issues.
- Vulnerabilities in repos you scan with this tool. Report those to the repo's owner.

## What this tool is and isn't

Git Gud Security finds candidate security issues and reports them as leads to confirm. It
is not a certifying authority. A clean scan is not a guarantee the target is safe, and a
finding is not proof the target is exploitable. Output from the standalone scanner is
unconfirmed candidates; confirmation happens when a human or the Claude Code skill reviews
each hit at its cited location.

It does not replace SAST/DAST, dependency scanning, secret-scanning services, or a real
penetration test. No warranty. See [LICENSE](LICENSE).

## Running it on untrusted code

`full` and `ultra` mode read a repo the scanner does not trust. They treat the target's
`.claude`/`.cursor`/`.gemini` settings, hooks, `mcp.json`, and instruction files as
findings to report, never as config to load or instructions to follow. If you run the
standalone scanner, it only reads and pattern-matches files; it does not execute the
target's code.
