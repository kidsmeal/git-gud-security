# Conventions

## Language and runtime
Python 3.8+. No third-party deps — stdlib only. All scripts run directly (`python scripts/scan.py`).

## File layout
- `scripts/` — the scanner: `scan.py` (main), `gate.py` (fetch/classify), `baseline.py` (snapshot), `build_checks.py`
- `scripts/patterns.json` — the pattern library (grep/config tier, data-driven)
- `scripts/checks.data.json` — structured source for the README red-flag phrase list
- `tests/run_tests.py` — golden-file test runner
- `tests/fixtures/` — hand-curated true-positive and false-positive trees
- `tests/expected/` — golden finding lists (normalized, hand-owned)

## Test discipline
Run: `python tests/run_tests.py`
Regenerate goldens only deliberately: `python tests/run_tests.py --update` — every golden change lands as a visible diff, which is the point.

When adding a pattern to `patterns.json`, add a matching fixture under `tests/fixtures/true-positives/` and update the golden. A pattern with no fixture test is untested.

## Pattern authorship (`patterns.json`)
Each entry needs: `id`, `category`, `severity`, `title`, `detectability`, `include`, `any` (list of regexes), `fix`. Optional: `not` (suppress list), `secret: true` (redacts the match), `entropy_gate: true` (doc/prose tier — only fire if the token has real entropy), `kind: "filename"` (presence check instead of content match).

Severity levels: `critical`, `high`, `medium`, `low`.
Detectability tiers: `grep`, `config`, `readme`, `trace` (trace-tier means the LLM does it in full/ultra; a grep proxy that fires at the deterministic tier is still labeled `grep`).

Install-time categories (fire on load, gate blocks on these): `claude-ext`, `mcp`, `ai-config-trust`, `supply-chain`. Add a new category to `install_time_categories` in `patterns.json` to make it gate-blocking.

## Engine stamp
Every finding the standalone script emits gets `"engine": "deterministic"`. The skill stamps its trace/adversarial findings `"llm"`. Never conflate them — the engine drives CI gating policy (deterministic findings can hard-fail; a single-pass LLM finding is a warning).

## Output formats
`json` (default, for the skill), `sarif` (GitHub code scanning, one run per engine), `text` (terse, pre-commit), `gate` (pre-install verdict). Add a format by adding a `to_<fmt>()` function in `scan.py` and wiring it in `main()`.

## Security invariants — do not break
- The gate (`--url`) never honors a `--baseline`. A hostile target must not be allowed to grandfather its own findings.
- `EXCLUDE_GLOBS` is operator-supplied on the CLI only. The scanner never reads an ignore list from inside the target repo.
- The `scrub()` function must cover every token format that `patterns.json` detects. A token on a line that matches a non-secret pattern would otherwise print verbatim. Keep `_SECRET_RE` a superset.
- Long lines are scanned in overlapping windows (`MAX_LINE_LEN` / `LINE_WINDOW_OVERLAP`) — never truncate a line and skip the rest.
- The gate clone uses `protocol.allow=never` + an explicit allowlist. Never widen `ALLOWED_PROTOCOLS` in production; the test suite overrides it for local fixture clones only.
