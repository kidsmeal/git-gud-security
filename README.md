# Git Gud Security

Security scanner for repos. 331 checks across 19 categories. Runs as a Claude Code skill or as a standalone Python script.

Covers app security (Supabase, Firebase, Cloudflare Workers, Next.js, Flutter, Expo) and the AI tooling surface (MCP servers, Claude skills/plugins/hooks, coding-agent config files, prompt injection in instruction files). Finds secrets, auth gaps, injection sinks, business logic holes, supply chain risks, CI/CD misconfig.

## Install

Clone into your skills directory:

```bash
git clone https://github.com/kidsmeal/git-gud-security ~/.claude/skills/git-gud-security
```

Windows: `%USERPROFILE%\.claude\skills\git-gud-security`

Then ask Claude Code:

```
scan this repo for security holes
git gud quick on .
is this safe to ship?
```

## Modes

| Mode | What it reads | What it catches |
|---|---|---|
| `readme` | README, docs, visible manifests | holes betrayed by claims and red-flag phrases |
| `quick` | readme + deterministic pattern/secret/config sweep | exposed secrets, dangerous code patterns, misconfig |
| `full` | quick + code reading and dataflow tracing | injection/SSRF reachability, IDOR, missing authz, deps, CI/CD |
| `ultra` | full as an adversarial multi-agent workflow | everything, each finding survives independent refutation before reporting |

Default is `quick`. Each mode is a strict superset of the one below it.

`readme` is the cheapest pass. It catches more than you'd expect because a lot of projects advertise their own holes in their docs ("just paste your service key here", "RLS disabled for easy local dev"). Findings are marked as inferred, not confirmed, unless the README literally shows the vulnerable thing.

`quick` runs a deterministic pattern sweep on top of the readme pass. It greps for secret formats, known-dangerous code patterns, and config red flags using `scripts/patterns.json` (79 patterns). Every hit is confirmed at the source line before reporting. Fast, low false-positive rate, catches the things that actually burn people.

`full` reads the code and traces dataflow. This is where injection sinks, SSRF, IDOR, broken multi-tenant isolation, and missing per-object authorization checks get caught. It also audits RLS policies, CI/CD workflows, and dependency hygiene. Slower, but it finds the holes that pattern matching can't reach.

`ultra` runs the full scan as an adversarial multi-agent workflow. Every finding goes to independent skeptics prompted to refute it. A finding only survives if the majority confirm it's real and reachable. This keeps the false-positive rate near zero at the cost of more tokens.

`full` and `ultra` treat the scanned repo as untrusted. They won't honor its hooks, `.claude`/`.cursor` settings, or `.mcp.json`. Those files are findings to report, not config to load.

## Standalone scanner

The deterministic sweep runs without Claude Code (Python 3.8+, no deps):

```bash
python scripts/scan.py /path/to/repo --mode quick
```

Outputs JSON. Secrets are redacted. This is the grep/config tier only.

## Check library

[`references/checks.md`](references/checks.md) has the full library. [`references/readme-redflags.md`](references/readme-redflags.md) is the fast lookup for readme mode.

To add or change checks, edit `scripts/checks.data.json` and rebuild:

```bash
python scripts/build_checks.py
```

`scripts/patterns.json` is the scanner's pattern set (grep/config subset, linked by id). `references/ultra-workflow.md` is the adversarial workflow for ultra mode.

## Limitations

Best-effort. Findings are leads to confirm, not guarantees. Does not replace SAST/DAST, dependency scanning, or pen testing. No warranty.

## License

MIT. See [LICENSE](LICENSE).
