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
- The pre-install gate (`scripts/scan.py --url`) letting a hostile URL escape its
  isolated, read-only fetch: executing the target's code, honoring its config/hooks/
  `mcp.json`, or fetching over a transport that allows local command execution (`ext::`)
  or local file reads (`file://`).
- Suppression bypass: the scanner reading an ignore/suppression list from inside a
  scanned repo, or the gate honoring a `--baseline` against an untrusted target, either of
  which would let a hostile repo hide its own findings.

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

The pre-install gate (`scripts/scan.py --url`) is built for exactly this: it fetches an
untrusted skill / MCP server / plugin from a URL and scans it before you install it. The
fetch is hardened against a repo written to attack the scanner: a shallow clone into an
isolated temp dir, a git protocol allowlist (https/git only, so `ext::` command execution
and `file://` local reads are refused), an isolated HOME with system/global git config
off, no submodule recursion, a size cap, and a timeout. The target is never executed. The
gate never honors the target's config, and never honors a `--baseline` against it, so a
hostile repo cannot suppress its own findings.

Suppression is operator-controlled, never repo-controlled. GGS does not read any ignore or
suppression file from inside a scanned repo. A `--baseline` is an explicit snapshot you
pass on the command line; it is enumerated (not an open-ended glob), it is reported
whenever it hides a finding, and it is audited for entries that grandfather a critical or
install-time finding.
