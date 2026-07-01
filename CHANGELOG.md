# Changelog

All notable changes to Git Gud Security are recorded here. Versioning is
[SemVer](https://semver.org/). Pre-1.0: behavior and check IDs may still change between
minor versions.

## [0.5.0] - 2026-06-30

Docs-secret coverage. Closes a real gap: the check library lists a live credential pasted into a
README or docs as a finding (`secret-in-readme-or-docs`), but no deterministic pattern implemented
it. Secret patterns excluded `.md`/`.txt` to avoid drowning in the placeholder keys docs are full
of, so a *real* pasted `ghp_`/`sk-ant-`/`AKIA` key slipped through the fast scan.

### Added

- **`secret-in-readme-or-docs` (81st pattern).** Scans `.md`/`.mdx`/`.txt` for provider-prefixed
  key formats (GitHub, OpenAI, Anthropic, AWS, Google, Slack, Stripe, and the AI/infra prefixes).
  81 patterns now, up from 80. The check library is unchanged at 332 (this implements a check that
  already existed).
- **Live-vs-placeholder entropy gate.** The doc tier only fires when the matched *token* reads as a
  live key: it's dropped on a placeholder marker (`xxx`, `your`, `example`, …), low Shannon entropy
  (`ghp_AAAA…`), a long single-char run, or a sequential run (`ghp_abcdef…`). Crucially it gates on
  the token, not the surrounding line, so a real key sitting next to a "replace with your key"
  comment still fires. Tuned to favor a rare miss over a false positive.

### Tests

- A true-positive fixture (a live-looking token in a `.md`) and a false-positive fixture (a page of
  placeholder keys) that must stay silent, plus the regenerated `quick` golden.

## [0.4.1] - 2026-06-30

Bug fix and CI hygiene.

### Fixed

- **Gate `owner/repo` shorthand on Linux/macOS.** `scan.py --url owner/repo` (and the skill's
  "git gud gate owner/repo") wrongly rejected the shorthand on POSIX since 0.3.0: `resolve_url`
  used `os.sep in spec` to detect local paths, but `os.sep` is `/` on POSIX, so every
  `owner/repo` was refused. The full `https://` form was unaffected. The shape regex already
  rejects local paths / scp-style targets, so the buggy check is gone. The test suite (which
  runs on Linux in CI) now covers the absolute-path / multi-segment / Windows-path reject cases.

### Changed

- **`action.yml` builds `--exclude` as a bash array** (`read -ra`) instead of an unquoted string,
  so a glob exclude (`scripts/*.json`, a 0.4.0 capability) reaches the scanner literally instead
  of being shell-expanded against the runner's cwd.
- The Action-manifest test no longer needs PyYAML, so CI runs it instead of skipping; its
  expression-injection guard now flags `${{ }}` only inside a `run:` block (env/with/if is safe).
- README: shields.io badges (CI, release, license, Python, no-deps).

## [0.4.0] - 2026-06-30

Adoption: drop GGS into an existing repo without drowning in pre-existing findings, and scope CI
to what a change actually touched. No new checks; the library is unchanged at 332. The deliberate
non-feature here is just as important — **GGS ships no in-repo ignore file.** A suppression file
the scanner reads from inside a repo is the one input an attacker most wants to write to (a
hostile repo would ship a `.ggsignore` that hides its own findings). Scope comes from the operator
(CLI flags) or from what changed (diff), never from a file discovered in the target.

### Added

- **`--baseline FILE`.** Filter findings against an enumerated snapshot so a scan reports and
  gates only on findings **new** since the snapshot. `--update-baseline` writes it (a deliberate
  act; grandfathering a finding shows up as a line in the file's diff). Chosen over an open-ended
  ignore-glob on purpose: a glob suppresses an unbounded future space including payloads not yet
  written, while a baseline can't — a new finding isn't in the snapshot, so it still fails.
- **Baseline integrity.** Entries are fingerprinted by `id + file + redacted evidence`,
  line-independent so an unrelated edit doesn't silently un-suppress. Suppression is observable: a
  `N suppressed by baseline` line plus the suppressed findings in JSON, never dropped silently. The
  baseline is audited — grandfathering a critical or install-time finding prints a loud warning, so
  broadening it to bury a critical trips the tool. The `--url` gate **never** honors a baseline (a
  hostile target can't grandfather its own findings); it's rejected up front.
- **`--diff REF`.** Scan only files changed against a ref (`--diff origin/main`), the CI adoption
  path: fail only on what a branch/PR changed, not the whole history. Like `--staged`, it scans
  tracked changes. Mutually exclusive with `--staged`.
- **`--exclude` path globs.** `--exclude` now takes path globs (`scripts/checks.data.json`,
  `**/*.min.js`), not just bare dir names — operator-supplied on the CLI, never read from inside a
  repo. This is the self-scan corpus fix: excluding the pattern DB drops our own scan from 61
  candidate findings to a handful (prose mentions in docs).

### Tests

- `--exclude` glob scoping, `--diff` scope, baseline write/load/partition, line-independent
  fingerprint, the audit flagging a grandfathered critical, and the gate refusing `--baseline`.

## [0.3.0] - 2026-06-30

The pre-install gate: vet an untrusted skill / MCP server / plugin from a URL **before** it
touches your machine. Every prior mode assumed you already trusted the code enough to check it
out. The gate inverts that and scans agent code, from a URL, before install. No new checks; the
library is unchanged at 332. JSON is still the default for a local scan, so the skill and the
pre-commit/Action paths are unaffected.

### Added

- **`scan.py --url <url|owner/repo>`.** Fetches an untrusted target into an isolated temp dir
  (never `~/.claude`, never the cwd), classifies it (skill / plugin / MCP / agent-config / app),
  scans it, and prints a go/no-go verdict. The target is **never executed** — static read only.
  `--ref` pins a branch/tag; the verdict names the exact commit SHA vetted.
- **Hardened fetch.** The repo is written by someone trying to attack the scanner, so the clone
  uses a git protocol allowlist (https/git only — no `ext::` command-exec, no `file://` local
  read), an isolated HOME with system/global git config off, no submodule recursion, no
  clone-time template hooks, a wall-clock timeout, and a post-clone size ceiling. Temp clones are
  always cleaned up (Windows read-only git objects included).
- **`--format gate`.** A three-level verdict — **DO NOT INSTALL** (a critical/high that fires at
  install/load time), **REVIEW FIRST** (real findings, none that fire on load), **LOOKS CLEAN**
  (within the mode's reach) — with install-time risks surfaced above ordinary app-sec findings,
  and a footer naming what was checked and that the code was not run. The default format for
  `--url`. The blocking surface is data-driven: an `install_time_categories` set in
  `patterns.json` (`claude-ext`, `mcp`, `ai-config-trust`, `supply-chain`), and every finding now
  carries an `install_time` flag in JSON.
- **`--keep`.** With `--url`, leaves the hardened checkout in place and prints its path so the
  skill's `full`/`ultra` tiers can read it under the hostile-repo posture instead of re-cloning
  unsafely.
- **Skill gate flow.** SKILL.md routes a URL + install intent ("is this skill safe to install?",
  "git gud gate `<url>`") to the gate, leads with the verdict, and writes `INSTALL_GATE.md`.

### Tests

- Gate oracle in `run_tests.py`: URL resolution + protocol refusal (ext/file/ssh/scp/bare-path),
  artifact classification, the hardened clone (pinned SHA, size cap, no stranded temp dir, ext::
  refused by the clone itself), the three verdict thresholds, and `--format gate` end to end
  against a malicious-skill and a clean-skill fixture.

## [0.2.0] - 2026-06-30

Adds the workflow integrations the deterministic tier was missing: a pre-commit hook, SARIF
output for GitHub code scanning, and a staged-files fast path. No new checks; the check
library is unchanged at 332. The default output format is still JSON, so the skill is
unaffected.

### Added

- **Pre-commit hook.** `.pre-commit-hooks.yaml` ships two hooks — `git-gud-security`
  (scans staged files, blocks the commit on high+ findings) and `git-gud-security-warn`
  (same scan, warn-only). Point `.pre-commit-config.yaml` at the repo and `pre-commit
  install`. Answers the most-asked question: yes, it hooks into pre-commit.
- **`--staged`.** Scans only files staged for commit (`git diff --cached`), so the
  pre-commit path stays fast on big repos. Falls back to a whole-tree scan with a notice
  when git isn't present. Committed and unstaged changes are out of scope by design.
- **`--fail-on {critical,high,medium,low}`.** Exits nonzero when a finding at or above the
  given severity is present, so a hook or CI step can block. Opt-in: findings are
  candidates, so the default still exits 0.
- **`--format {json,sarif,text}`.** `sarif` emits SARIF 2.1.0 (one rule per check id,
  `security-severity` set) for the GitHub Security tab and inline PR annotations; `text` is
  a terse human summary for the pre-commit path. `json` stays the default; `--json` is kept
  as an alias.
- **Per-engine SARIF runs.** SARIF output is split into one run per engine — `deterministic`
  (this script) and `llm` (the skill's dataflow/adversarial findings) — each with its own
  `automationDetails.id` (`git-gud-security/deterministic`, `git-gud-security/llm`), so GitHub
  renders them as distinct analyses and CI can gate them independently (hard-fail deterministic,
  warn on single-pass llm). Every finding now carries an `engine` field in JSON too. The
  standalone script only produces deterministic findings, so today that's a single run.
- **GitHub Action.** A reusable composite action (`action.yml`) so a repo gets a CI scan with
  SARIF upload by adding `uses: kidsmeal/git-gud-security@v0.2.0` to a workflow. Annotates by
  default (findings are candidates); `fail-on:` blocks. Inputs passed via `env`, never
  interpolated into the run script, to avoid the Actions expression-injection hole this tool
  itself flags.
- **`docs/pre-install-gate.md`** — spec for the 0.3.0 headline: vetting a third-party skill /
  MCP / plugin from a URL before it's installed.

### Tests

- SARIF validity (result-per-finding, 1-based regions, rules present), `--fail-on` exit
  codes (blocks when dirty, passes when clean, never blocks without the flag), and
  `--staged` scope (a throwaway git repo proves only staged files are scanned).

## [0.1.1] - 2026-06-30

Bug-fix release. No new checks. Scan output changes: some findings are now correctly
critical (were under-rated), and secrets in minified bundles are now found, so a scan of
the same repo may surface more than v0.1.0 did.

### Fixed

- **Severity drift (correctness).** 26 of 80 patterns emitted a severity one level below
  the source-of-truth check library (e.g. `service-role-key-in-client` was `high` vs the
  library's `critical`), under-grading findings. Synced to `checks.data.json`.
- **Incomplete redaction (safety).** A SendGrid / Twilio / DigitalOcean token on a line
  that also matched a non-secret pattern printed in cleartext, because the global scrub
  regex wasn't a superset of the formats the patterns detect. Added the missing formats.
- **Minified-bundle coverage.** A secret past byte 5000 of a one-line bundle was missed
  because each line was truncated before matching. Long lines are now scanned in
  overlapping windows, so the whole line is covered while each match stays bounded.

### Tests

- Findings are asserted against exact `(id, file, line, severity)` goldens (fail on missing
  or extra), regenerated only via `--update`. Added locks for severity sync, scrub coverage,
  redaction (no token in cleartext), and long-line bundle coverage.

## [0.1.0] - 2026-06-30

First tagged release. Usable, not yet API-stable.

### Scanner

- Deterministic standalone sweep (`scripts/scan.py`, Python 3.8+, no deps) over the
  grep/config tiers. Emits JSON; secrets redacted in output.
- `readme` mode: prose red-flag phrase scan against the phrase library, plus config and
  filename checks. Matches are marked `inferred`.
- `quick` mode: the full pattern sweep on top of readme, plus a secret/sourcemap sweep of
  build-output dirs (`dist`, `build`, `.next`, `out`, `.nuxt`, `.svelte-kit`).
- `full` / `ultra` are skill-only (they need an LLM for dataflow tracing and adversarial
  verification); the script exits with a pointer if invoked standalone.
- `--exclude` to skip additional directories. `--version` to print the version.

### Check library

- 332 checks across 19 categories (`scripts/checks.data.json`, rendered to
  `references/checks.md` and `references/readme-redflags.md` by `scripts/build_checks.py`).
- 80 deterministic patterns (`scripts/patterns.json`), pattern IDs aligned to check IDs.
- Coverage includes app security (Supabase/Firebase/Workers/Next.js/Flutter/Expo) and the
  AI tooling surface (MCP servers, Claude skills/plugins/hooks, coding-agent config files,
  prompt injection in instruction files).

### Skill

- Four modes (readme/quick/full/ultra) driven by per-check detectability tiers.
- Treats scanned repos as untrusted in full/ultra: their hooks, agent settings, and
  `mcp.json` are findings to report, never config to load.

### Tests & CI

- Fixture-backed test runner (`tests/run_tests.py`): per-pattern coverage (all 80 fire),
  zero false positives on safe fixtures, JSON validity, documented-count and pattern/check
  ID alignment checks.
- GitHub Actions runs the suite on push and PRs across Python 3.8 and 3.12.

[0.2.0]: https://github.com/kidsmeal/git-gud-security/releases/tag/v0.2.0
[0.1.1]: https://github.com/kidsmeal/git-gud-security/releases/tag/v0.1.1
[0.1.0]: https://github.com/kidsmeal/git-gud-security/releases/tag/v0.1.0
