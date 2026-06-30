<h1 align="center">Git Gud Security</h1>

<p align="center"><em>Simple security for solo devs building with AI. Protect yourself and protect others.</em></p>

<p align="center">
  <a href="https://github.com/kidsmeal/git-gud-security/releases"><img src="https://img.shields.io/github/v/release/kidsmeal/git-gud-security" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/kidsmeal/git-gud-security" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/python-3.8%2B-blue" alt="Python 3.8+">
</p>

A free security tool for solo AI devs: check the skills, MCP servers, agents, and apps you build before you ship them, without paying for a service. No account, no subscription. The fast scan runs entirely on your machine.

Most of what burns people isn't exotic: a service_role key pasted into the frontend, RLS left off "for dev," a committed `.env` with live keys, an MCP tool that runs `exec()` on model-supplied input, a SKILL.md trying to redirect your agent. It looks for those and reports them plainly, with the file and line.

Built for the AI tooling surface the free scanners ignore (MCP servers, Claude skills/plugins/hooks, coding-agent config files, prompt injection in instruction files), with coverage of the app behind it too (Supabase, Firebase, Cloudflare Workers, Next.js, Flutter, Expo). Runs as a Claude Code skill or as a standalone Python script with no dependencies.

## Install

Clone into your skills directory. Pin to a release tag (recommended for a security tool, so you know exactly what's running):

```bash
git clone --branch v0.4.1 https://github.com/kidsmeal/git-gud-security ~/.claude/skills/git-gud-security
```

Or track the latest:

```bash
git clone https://github.com/kidsmeal/git-gud-security ~/.claude/skills/git-gud-security
```

Windows: `%USERPROFILE%\.claude\skills\git-gud-security`. Releases and changelog: [CHANGELOG.md](CHANGELOG.md).

Then ask Claude Code:

```
scan this repo for security holes
git gud quick on .
is this safe to ship?
```

## Modes

Start free and instant, go deeper only if you want to. The first two modes run locally with nothing but Python. The deeper two read your code with an LLM, so they cost tokens in your own Claude Code.

| Mode | What it reads | What it looks for | Cost |
|---|---|---|---|
| `readme` | README, docs, visible manifests | holes betrayed by claims and red-flag phrases | free, local |
| `quick` | readme + deterministic pattern/secret/config sweep | exposed secrets, dangerous code patterns, misconfig | free, local |
| `full` | quick + code reading and dataflow tracing | injection/SSRF reachable from user input, IDOR, missing authz, deps, CI/CD | your Claude Code tokens |
| `ultra` | full as an adversarial multi-agent workflow | the same, each finding refuted before it's reported | many tokens (see below) |

Default is `quick`. Each mode is a strict superset of the one below it. `readme` and `quick` need only Python; `full` and `ultra` need Claude Code because they use the model to read code.

`readme` is the cheapest pass. It catches more than you'd expect because a lot of projects advertise their own holes in their docs ("just paste your service key here", "RLS disabled for easy local dev"). Findings are marked as inferred, not confirmed, unless the README literally shows the vulnerable thing.

`quick` runs a deterministic pattern sweep on top of the readme pass. It greps for secret formats, known-dangerous code patterns, and config red flags using `scripts/patterns.json` (80 patterns). Every hit is confirmed at the source line before reporting. Fast, low false-positive rate, catches the things that actually burn people. This is the everyday mode, and it's free.

`full` reads the code and traces dataflow. This is where it looks for injection sinks, SSRF, IDOR, broken multi-tenant isolation, and missing per-object authorization checks. It also audits RLS policies, CI/CD workflows, and dependency hygiene. It reaches holes pattern matching can't, but it reads your code with an LLM, so what it finds depends on the model and it costs tokens in your own Claude Code.

`ultra` runs the full scan as an adversarial multi-agent workflow. Every finding goes to independent skeptics prompted to refute it, and only survives if the majority confirm it's real and reachable. That verification pass makes ultra's findings the most trustworthy and makes it by far the most expensive mode: it fans out many agents per category and loops until two rounds turn up nothing new, so a single ultra run can be hundreds of model calls. Reach for it when a miss is costly (a public launch, or shipping a tool other people will install), not for a routine check. For everyday scans, `quick` is free and `full` is enough.

`full` and `ultra` treat the scanned repo as untrusted. They won't honor its hooks, `.claude`/`.cursor` settings, or `.mcp.json`. Those files are findings to report, not config to load.

## Standalone scanner

The deterministic tiers run without Claude Code (Python 3.8+, no deps):

```bash
python scripts/scan.py /path/to/repo --mode quick
python scripts/scan.py /path/to/repo --mode readme
python scripts/scan.py /path/to/repo --mode quick --exclude references tests fixtures
```

The script does the two deterministic modes: `readme` (prose red-flag phrase scan + config/filename checks) and `quick` (that plus the full pattern sweep and a secret/sourcemap sweep of build output). `full` and `ultra` need an LLM for dataflow tracing and adversarial verification, so they only run through the skill; the script exits with a pointer if you ask for them.

Outputs JSON by default. Secrets are redacted. Output is **candidate findings**, not confirmed vulnerabilities. Each hit needs human or LLM review at the cited `file:line` to confirm it's real (not a comment, test fixture, example, or safe public key); readme-tier matches are inferred from prose and marked `inferred`. When run as a Claude Code skill, that confirmation step happens automatically. When run standalone, you're looking at raw candidates.

Flags for hooking into a workflow:

| Flag | Effect |
|---|---|
| `--staged` | scan only files staged for commit (`git diff --cached`) — the pre-commit fast path |
| `--diff <ref>` | scan only files changed against a ref (`--diff origin/main`) — fail only on what a branch/PR changed |
| `--baseline <file>` | report/gate only on findings *new* since the snapshot in `<file>`; `--update-baseline` writes it |
| `--fail-on critical\|high\|medium\|low` | exit nonzero if a finding at or above that severity is present, so a hook or CI step blocks |
| `--format json\|sarif\|text` | `json` (default), `sarif` for GitHub code scanning, `text` for a terse human summary |
| `--exclude <dir\|glob>` | skip dirs or path globs (`--exclude tests scripts/checks.data.json`) |

### Adopting on an existing repo

A repo with pre-existing findings shouldn't have to fix everything before CI goes green. Two ways, neither of which is an in-repo ignore file the scanner trusts (that's the one input an attacker most wants to write to):

```bash
# Snapshot today's findings, then fail only on NEW ones. The baseline is enumerated, so
# grandfathering anything shows up as a line in its diff; suppressed findings are still shown.
python scripts/scan.py . --mode quick --baseline .ggs-baseline.json --update-baseline
python scripts/scan.py . --mode quick --baseline .ggs-baseline.json --fail-on high

# Or scope CI to the diff: fail only on findings your branch introduced.
python scripts/scan.py . --mode quick --diff origin/main --fail-on high
```

Suppression is never silent: a `N suppressed by baseline` line plus the suppressed findings ride along in the output, and the baseline is audited — grandfathering a critical or install-time finding prints a loud warning. The pre-install gate (`--url`) never honors a baseline.

## Pre-commit hook

Scan staged files on every commit and block on high+ findings. Needs the [pre-commit](https://pre-commit.com) framework (`pip install pre-commit` or `pipx install pre-commit`). Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/kidsmeal/git-gud-security
    rev: v0.4.1
    hooks:
      - id: git-gud-security        # blocks the commit on high+ findings
      # - id: git-gud-security-warn # or: print findings without blocking
```

Then `pre-commit install`. The hook runs `--mode quick --staged --fail-on high`; override `args:` in your config to change the mode or threshold. Findings are candidates, so the warn-only hook is there if you'd rather surface than block.

## GitHub Action

Scan every push and PR, with findings posted inline on the PR and into the Security tab. Add a workflow to your repo:

```yaml
# .github/workflows/security.yml
name: git gud security
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # required to upload to code scanning
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: kidsmeal/git-gud-security@v0.4.1
        # with:
        #   mode: quick            # or readme
        #   exclude: tests vendor  # dirs to skip
        #   fail-on: high          # block the build on high+ (default: annotate only)
```

By default it annotates without failing the build (findings are candidates). Set `fail-on:` to block. Code scanning is free on public repos; private repos need GitHub Advanced Security.

To run the scan in CI without the Action (or to upload the SARIF yourself):

```bash
python scripts/scan.py . --mode quick --format sarif --out ggs.sarif
# then: github/codeql-action/upload-sarif with sarif_file: ggs.sarif
```

SARIF is split into one **run per engine** — `deterministic` (this script) and `llm` (the skill's dataflow/adversarial findings) — each with its own `automationDetails.id`, so GitHub renders them as separate analyses and you can gate CI on each independently (hard-fail deterministic, warn on single-pass llm). Every finding also carries an `engine` field in the JSON output. The standalone script only produces deterministic findings, so on its own it emits a single run.

## Install gate (vet a URL before you install it)

Every mode above scans a repo you already trust enough to check out. The gate is the opposite
motion: it scans an **untrusted** skill, MCP server, or plugin **from a URL, before it touches
your machine**. This is the audience this tool is built for: people installing agent tooling.

Through the skill, conversationally:

```
git gud, is this skill safe to install?  https://github.com/someone/their-skill
git gud gate someone/their-mcp-server
is it safe to add this MCP server? <url>
```

Or standalone:

```bash
python scripts/scan.py --url someone/their-skill            # owner/repo or a full https URL
python scripts/scan.py --url https://github.com/x/y --ref v1.2.0
```

It shallow-clones the target into an isolated temp dir (never `~/.claude`, never your cwd),
classifies it, scans it, and prints a verdict. The target is **never executed** (static read
only), and the fetch is hardened against a repo built to attack the scanner: a git protocol
allowlist (https/git only, no `ext::` command-exec or `file://` local-read), an isolated HOME, no
submodule recursion, a size cap, and a timeout.

```
Git Gud Security — install gate · their-skill @ 9f3c1a2b

  Verdict: DO NOT INSTALL   install-time: 1 critical · 0 high   ·   all: 1 critical · 1 high · 0 medium · 0 low
  Artifact: skill

INSTALL-TIME RISKS  (fire the moment you load this)
  1. CRITICAL hook-exfiltrates-env-or-credentials      hooks/session-start.sh:4
     fix: A hook that reads env/SSH/.aws and POSTs to a remote is exfiltration. Remove it and rotate.
...
```

Three verdicts: **DO NOT INSTALL** (a critical/high that fires at install/load time), **REVIEW
FIRST** (real findings, none that fire on load), **LOOKS CLEAN** (within the mode's reach).
Install-time risks (hooks, MCP/tool defs, config-that-runs-on-open, install scripts,
instruction-file injection) are surfaced above ordinary app-sec findings. The verdict is the
deterministic quick tier; ask for full or ultra to trace reachability before trusting a LOOKS CLEAN.

## Check library

[`references/checks.md`](references/checks.md) has the full library: 332 checks across 19 categories. Of those, 80 are wired into the standalone scanner as deterministic patterns; the rest are reasoned about by the LLM in `full`/`ultra`. [`references/readme-redflags.md`](references/readme-redflags.md) is the fast lookup for readme mode.

To add or change checks, edit `scripts/checks.data.json` and rebuild:

```bash
python scripts/build_checks.py
```

`scripts/patterns.json` is the scanner's pattern set (grep/config subset, linked by id). `references/ultra-workflow.md` is the adversarial workflow for ultra mode.

## Limitations

Best-effort. Findings are leads to confirm, not guarantees. Does not replace SAST/DAST, dependency scanning, or pen testing. No warranty.

## License

MIT. See [LICENSE](LICENSE).
