# Roadmap

Where Git Gud Security is going, and the line it won't cross to get there.

## Identity

A security scanner is a crowded space. On generic app-sec — injection, SSRF, secrets, RLS —
gitleaks, trufflehog, semgrep, and snyk are better-resourced at the deterministic tier, and
GGS treats solid coverage there as table stakes, not the pitch.

The edge is the surface those tools don't cover: the **AI/agent attack surface**. MCP servers
that shell out on model-supplied input, Claude skills/plugins/hooks that run code on open,
coding-agent and IDE config files that redirect your API key or auto-launch a server, prompt
injection buried in instruction files. As people clone third-party skills into `~/.claude` and
wire up MCP servers they never read, the tool you run *before* trusting that code is missing
from the market. GGS aims to be that tool.

So the direction is to **narrow, not broaden**: be the scanner for the AI/agent supply chain,
with generic coverage as the floor — not a generic scanner that also happens to check skills.

## Architecture line

The thing that keeps GGS both light and comprehensive is *where* each kind of work lives:

- **Deterministic stays in the script.** `scan.py` is single-file, no-deps, Python 3.8+. It
  does secrets, dangerous patterns, config red flags — anything a regex or a file-presence
  check can confirm. This is the "light, standalone" half. It must stay installable by `git
  clone` and runnable with nothing but a Python interpreter.
- **Semantic stays in the model.** Dataflow tracing (is this sink reachable from user input?),
  authz reasoning (does this check the right thing?), and adversarial verification live in the
  `full`/`ultra` skill modes, because they need an LLM. This is the "comprehensive" half.

Comprehensiveness comes from the model and the check library, **not** from piling more regexes
into the script. We will not port trace-tier logic into Python to chase coverage; that road
ends in a slow, false-positive-spewing tool nobody runs.

## Shipped

- **0.1.x** — deterministic standalone sweep (`readme`/`quick`), 332-check library across 19
  categories, 80 patterns, fixture-backed tests + CI, redaction, severity sync.
- **0.2.0** — pre-commit hook (`.pre-commit-hooks.yaml`), `--staged` fast path, `--fail-on`
  severity gate, SARIF 2.1.0 output for GitHub code scanning, terse `text` format.

## Next

Roughly in priority order. Each is meant to keep the script light and standalone.

1. **Baseline / suppression.** A `.ggsignore`-style baseline so an established repo can adopt
   GGS without drowning in pre-existing findings — only *new* findings fail. Without this, the
   first CI run's wall of candidates gets ignored and the tool dies in the pipeline. This is
   the gap that most limits adoption right now.
2. **Diff against a ref.** `--diff <ref>` (not just `--staged`) so CI can scan only what a PR
   changed against its base. Pairs with the baseline.
3. **Pre-install supply-chain gate.** `scan <github-url>` — fetch an untrusted third-party
   skill / MCP server / plugin into isolation and scan it *before* it lands in `~/.claude`.
   The "Scanning a hostile repo safely" section in SKILL.md is already the design; this is the
   front door. This is the headline feature that gives GGS an identity no other scanner has.
4. **Distribution that stays light.** `uvx git-gud-security` / pipx, and a published GitHub
   Action wrapping `quick` + SARIF upload. Adoption-light, zero new runtime deps.
5. **Sharpen the AI/agent categories.** Deepen MCP, skills/plugins/hooks, and coding-agent
   config-trust checks ahead of the generic ones — that's where the differentiation compounds.

## Non-goals

- Replacing SAST/DAST, dependency scanners, or pen testing. GGS produces leads to confirm.
- Runtime dependencies in the standalone script.
- Generic-checker feature parity for its own sake. If a finding needs a real semantic engine,
  it belongs in the LLM tier, not in a brittle Python heuristic.
