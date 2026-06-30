# Changelog

All notable changes to Git Gud Security are recorded here. Versioning is
[SemVer](https://semver.org/). Pre-1.0: behavior and check IDs may still change between
minor versions.

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

[0.1.0]: https://github.com/kidsmeal/git-gud-security/releases/tag/v0.1.0
