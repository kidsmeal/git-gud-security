# Architecture

## The two-tier model
The scanner is split by intent. The standalone script (`scripts/scan.py`) is the **deterministic tier**: no LLM, no network, fast enough for a pre-commit hook. The Claude Code skill is the **LLM tier**: dataflow tracing (full mode) and adversarial multi-agent verification (ultra). The script feeds JSON to the skill; the skill stamps its findings `engine: llm`, the script stamps its own `engine: deterministic`. They never merge into one process.

## Core modules
- `scan.py` — entry point and orchestrator. Walks the repo, runs all check tiers, emits findings in the requested format. Imports `baseline` and `gate` but neither imports `scan`.
- `gate.py` — pre-install gate. Two jobs: `safe_clone` (hardened shallow clone of an untrusted URL into a throwaway dir) and `classify` (decide what kind of artifact it is from on-disk signals). Lives separately because it handles hostile input and must never execute the target's code.
- `baseline.py` — enumerated-snapshot suppression. A baseline is a fingerprinted list of known findings, not a glob. The pre-install gate is hardcoded to refuse a baseline — a hostile target can't be allowed to grandfather its own findings.
- `patterns.json` — the whole grep/config pattern library. Adding a check here is the normal path; you rarely need to touch Python code for a new pattern.
- `checks.data.json` — structured source for the README red-flag phrase list. `scan.py` reads it at runtime via `load_readme_phrases()`; the references doc is generated from the same file.

## Scan flow (quick mode)
1. Resolve the file set: whole tree, or `--staged` / `--diff` subset.
2. Prose red-flag scan (`.md` / `.txt` files vs. phrases from `checks.data.json`).
3. Filename checks (presence of dangerous files).
4. `.env` hygiene check (independent of `patterns.json`).
5. Content scan: every grep/config pattern in `patterns.json` against every in-scope file.
6. Build-output sweep: secret/sourcemap patterns only, against `dist`/`build`/`.next` etc. (skipped by the normal walk, swept separately because leaked keys end up in bundles).
7. Merge, severity-sort, stamp `engine: deterministic`, apply baseline if given, emit.

`readme` mode skips steps 5 and 6 (config-tier content only, no grep).

## The gate path (`--url`)
`resolve_url` → `safe_clone` (isolated HOME, `protocol.allow=never`, depth-1, size cap, timeout) → `classify` (artifact kind from on-disk signals) → normal scan flow → `to_gate()` output (verdict: DO NOT INSTALL / REVIEW FIRST / LOOKS CLEAN). The workdir is always deleted unless `--keep` is passed (the skill passes `--keep` so full/ultra can read the checkout under the hostile-repo posture).

## Non-obvious constraints
- `EXCLUDE_GLOBS` is CLI-only. The scanner deliberately never reads an ignore file from inside the target repo — that would let a hostile target hide its own findings.
- The `scrub()` function must stay a superset of every token format `patterns.json` detects. A token on a line that matched a non-secret pattern would print verbatim otherwise.
- Long lines are scanned in overlapping windows, not truncated — a secret past byte 5000 in a minified bundle is still caught.
- `install_time_categories` in `patterns.json` controls which findings the gate surfaces first and blocks on (critical/high among them = DO NOT INSTALL). Adding a new category here is the only change needed to make it gate-blocking.
