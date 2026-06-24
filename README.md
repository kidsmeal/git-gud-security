# Git Gud Security

If you build alone, you ship the security holes alone too. No reviewer catches the service_role
key you pasted into the frontend, the RLS you turned off "just for dev", the `.env` you committed
at 2am. This points a scanner at your repo and finds that stuff before someone else does.

It also covers the tools a solo dev ends up building for themselves: Claude Code skills, plugins,
MCP servers, agents, slash commands, hooks. Those have their own class of holes now (an MCP tool
that runs `exec()` on whatever the model hands it, a hook that POSTs your env to a remote, a
SKILL.md carrying a prompt injection) and almost nothing checks for them yet. This does.

It runs as a [Claude Code](https://claude.com/claude-code) skill, so you just ask it to scan and
read the report. Normal app security too (Supabase, Cloudflare, Next, Expo), not only the Claude
stuff.

Findings are terse and cited. Every one points to a real hole at a `file:line` with a one-line
fix, or tells you what the current mode couldn't reach yet. The report opens with a letter grade.

## Modes

Four modes, each a strict superset of the one below it. Pick by how deep you want to go.

| Mode | Reads | Catches |
|---|---|---|
| `readme` | README, docs, landing copy, visible manifests | holes betrayed by claims and red-flag phrases |
| `quick` | readme + a deterministic pattern/secret/config sweep | exposed secrets, known-dangerous code patterns, misconfig |
| `full` | quick + reads the code and traces dataflow | injection/SSRF reachable from user input, IDOR, missing authz, deps, CI/CD |
| `ultra` | full, run as an adversarial multi-agent pass | everything, each finding refuted by independent skeptics before it's reported |

`readme` mode is the cheapest and often the most damning, because a lot of projects advertise
their own holes. `quick` is the default. `ultra` keeps the false-positive rate near zero by making
every finding survive a refutation panel.

## What it checks

312 checks across 19 categories, from glaring to subtle:

Secrets and credentials, auth and account lifecycle, database/RLS/cloud config, injection, SSRF
and traversal, web frontend and transport, file uploads, caching/CDN/DNS, cryptography and tokens,
realtime/WebSocket, business logic and payments, mobile, desktop apps and browser extensions, AI/
LLM/agent app security, MCP server security, Claude plugins/skills/hooks, AI coding-agent and
IDE-config trust, dependencies and supply chain, CI/CD.

The full library lives in [`references/checks.md`](references/checks.md). Each entry has a severity,
a detectability tier, the signals to grep for, the README phrases that betray it, an example, and
the fix. The README red-flag lookup is in [`references/readme-redflags.md`](references/readme-redflags.md).

## Install

It's a Claude Code skill. Clone it into your skills directory:

```bash
git clone https://github.com/kidsmeal/git-gud-security ~/.claude/skills/git-gud-security
```

On Windows that path is `%USERPROFILE%\.claude\skills\git-gud-security`.

Then in Claude Code, just ask:

```
git gud quick on .
scan this repo for security holes
is this safe to ship?
what holes can you find just from their readme: <url>
```

## Run the scanner without Claude

The deterministic sweep is a standalone Python script (no third-party deps, Python 3.8+):

```bash
python scripts/scan.py /path/to/repo --mode quick
```

It emits JSON findings (secrets are redacted). This is the grep/config tier only. The deeper holes
need dataflow and are handled by the model in `full`/`ultra` mode.

## How it's built

`scripts/checks.data.json` is the structured source of truth for the check library.
`scripts/build_checks.py` renders `references/checks.md` and `references/readme-redflags.md` from it.
To add or change checks, edit the data and rebuild:

```bash
python scripts/build_checks.py
```

`scripts/patterns.json` is the deterministic scanner's pattern set (the grep/config subset of the
library, linked back by `id`). `references/ultra-workflow.md` holds the adversarial multi-agent
workflow that powers `ultra` mode.

## Limitations

This is a best-effort assistant, not a guarantee. Treat its findings as leads to confirm. They
don't replace human review, a real SAST/DAST pass, dependency scanning, or a pen test. It misses
things and it flags false positives, which is why `quick` and `full` confirm at the source line
before reporting and `ultra` runs a refutation panel. It comes with no warranty.

## License

MIT. See [LICENSE](LICENSE).
