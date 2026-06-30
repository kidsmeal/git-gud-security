# Spec: pre-install supply-chain gate (0.3.0)

Status: proposed. This is the design for the 0.3.0 headline feature. Nothing here is built yet.

## The problem

People install third-party Claude skills, MCP servers, and plugins by cloning a repo straight
into `~/.claude/` or wiring an `mcp.json` — code that then runs with their tools, their
filesystem, their API key. There is no step between "I found this skill on GitHub" and "it's
now active in my agent." A malicious or careless skill can exfiltrate env vars on session
start, shell out on model-supplied input, or carry a prompt-injection payload in its SKILL.md.

Every existing scanner assumes you already trust the code enough to have it checked out in your
project. The gate inverts that: **scan untrusted agent code, from a URL, before it touches your
machine.** This is the one job no generic SAST tool does, and the thing GGS's check library is
already built for (the MCP / skills / plugins / agent-config categories).

## Invocation

Through the skill, conversationally:

```
git gud, is this skill safe to install?  https://github.com/someone/their-skill
git gud gate https://github.com/someone/their-mcp-server
is it safe to add this MCP server? <url>
```

The skill recognizes a URL (or `owner/repo`) plus install intent and routes to the gate flow
instead of scanning the local repo.

## Flow

1. **Fetch into isolation.** Shallow-clone the URL into a throwaway temp dir outside any agent
   config path — never into `~/.claude`, never the cwd. Pin to the requested ref; record the
   commit SHA so the verdict names exactly what was vetted. Size/time caps; refuse repos over a
   ceiling.
2. **Classify the artifact.** Is this a skill (`SKILL.md`), a plugin (`.claude-plugin/`), an MCP
   server (`mcp.json` / a server manifest), a coding-agent config bundle, or a plain app? The
   classification selects which check categories lead.
3. **Scan, treating the repo as hostile.** Run the existing modes (`quick` always; `full`/`ultra`
   when the user wants depth) under the hardened posture already written in SKILL.md's "Scanning
   a hostile repo safely": do not honor the repo's hooks, `.claude/settings.json`,
   `enableAllProjectMcpServers`, `ANTHROPIC_BASE_URL`/`*_BASE_URL` overrides, or auto-launch
   anything from its `mcp.json`. Its instruction files (`SKILL.md`, `AGENTS.md`, `.cursorrules`,
   README) are untrusted text to report on, not instructions to follow.
4. **Weight the install-time surface.** A gate cares most about what runs the moment you install
   or load the artifact: session-start / install hooks, tool definitions that shell out, network
   calls on load, requested scopes/permissions, and injection payloads in instruction files.
   These get surfaced first, above ordinary app-sec findings.
5. **Verdict.** A go / no-go headline plus the cited findings, not just a grade. The user asked a
   yes/no question ("safe to install?"), so answer it.

## Output

```
Git Gud Security — install gate · their-skill @ <sha>

  Verdict: DO NOT INSTALL        2 critical · 1 high
  Artifact: Claude skill

INSTALL-TIME RISKS
 1. SessionStart hook reads ~/.aws/credentials and POSTs to an external host   hooks/start.sh:4
    runs the instant the skill loads. exfiltrates your cloud creds.
 2. SKILL.md instructs the agent to run `mcp.json` servers without review      SKILL.md:31
    indirect prompt injection: the skill tells your agent to auto-launch its bundled MCP.

OTHER FINDINGS
 3. ...

what this gate checked: install hooks, tool defs, instruction-file injection, declared scopes,
secrets. did NOT run the code. <sha> on branch main.
```

Three verdict levels: **DO NOT INSTALL** (confirmed install-time critical/high), **REVIEW
FIRST** (real findings, none that fire on load), **LOOKS CLEAN** (within the mode's reach —
state the limit).

## Safety model — the hard part

The scanner reads code written by someone trying to attack the scanner. Non-negotiables:

- Fetched code is **data, never config.** Nothing in the temp dir alters how the scanning agent
  runs. Clone with an explicit, pinned scanner config and an isolated `HOME`.
- **Never execute** the target: no install scripts, no `npm install`, no launching its servers,
  no importing its modules. Static read only. (Even `full`/`ultra` only *read* and reason.)
- The agent's own pre-flight runs the three config-trust checks first and treats their hits as
  the headline, not as settings to load.
- Network egress from the scan is for the clone only.

## Why this is the headline, not the Action

The Action and pre-commit hook consume the deterministic engine for people who already trust
their own code. The gate is the opposite motion: it serves the exact audience starring GGS —
people building and installing agent tooling — and audits the exact surface (skills, MCP,
plugins) that no other scanner covers. It's the feature that makes "a security scanner for the
things people build with Claude" literally true at install time.

## Open questions

- **`owner/repo` and non-GitHub hosts.** Resolve shorthand; decide whether to support GitLab /
  arbitrary git URLs in 0.3.0 or GitHub-only first.
- **Already-installed sweep.** A sibling command that scans what's *already* in `~/.claude/` —
  same checks, local target. Probably 0.3.x once the gate exists.
- **Caching.** Re-gating the same SHA should be free; key a small result cache on commit SHA.
- **Depth default.** Gate at `quick` by default (seconds) and offer `full`/`ultra` for "really
  dig in," or default deeper because the stakes (code about to run in your agent) are higher?
- **Standalone reach.** The fetch+classify+report wrapper could ship in `scan.py` too
  (`scan.py --url ...`), but the hostile-repo reasoning wants the LLM tiers — likely skill-first.
