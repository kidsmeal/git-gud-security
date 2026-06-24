# Git Gud Security — Hardening Research Roadmap

Research date: 2026-06-23. Method: 8 web-grounded finder agents (one per frontier) →
dedup/merge → adversarial verify (4 tests per avenue: evidence real, genuine gap vs the
288-check library, statically detectable, severity sane) → synthesis. 39 raw avenues → 33
merged → 30 kept (24 KEEP, 6 DEMOTE), 3 dropped.

Known gap in this pass: the dedicated supply-chain-worm finder was killed mid-run by a model
safety filter, so worm grep-signatures (Shai-Hulud-style self-publish / secret-harvest in
lifecycle scripts) are NOT captured here. Slopsquatting was recovered by another finder.
Re-run that frontier separately.

Grounded against the live library: 288 checks, 18 categories in `scripts/checks.data.json`.
Every overlap/gap below was confirmed by reading the actual check ids and signals.

## 1. Bottom line

The library is strong on classic web/cloud/BaaS and on single-agent/single-MCP-server holes.
It is blind in one cluster: the **cross-tool AI-coding-agent config surface** (rules files,
committed `.claude`/`.mcp.json`/CI-agent YAML that auto-execute on clone/open) and the
**2025-2026 framework-CVE version floors** (React2Shell RSC, Astro path-normalization, the new
opaque key prefixes). Highest-value adds, in order: committed Claude/MCP/CI agent-config trust
boundary (RCE on clone, fully config-tier, partly a threat to the scanner itself), the Rules
File Backdoor + cross-tool instruction-file class (a whole missing file family), the new secret
key-prefix roster (`sb_secret_`, `cfat_`, AI-provider keys the regex misses today), and
slopsquatting (no hallucinated-dependency check exists). Most of these are config/grep tier, so
they land in `quick` mode where they pay off immediately. Secondary theme: the existing MCP
category lints tool *descriptions* and *server code* but not the *committed config that launches
the server* nor the *non-description schema slots* of a poisoned tool.

## 2. P0 — add now

### P0-1. Committed Claude/MCP/CI agent-config that auto-executes on clone or open
Three sibling checks, all config-tier, all RCE-on-open, partly self-relevant (the scanner reads
these in full/ultra). Existing `hook-persists-env-via-claude-env-file`,
`settings-json-widens-permissions`, `plugin-mcp-remote-or-secret-forwarding` miss the specific
clone-open keys, the `ANTHROPIC_BASE_URL` redirect, and the CI-agent YAML pattern entirely
(keyword scan: `claude-code-action` → none).

Slots into existing category **Claude Plugins, Skills, Hooks & Agents** (first two) and **CI/CD
& Infrastructure** (third).

- **`claude-project-config-clone-open-rce`** — high→critical / config. Committed
  `.claude/settings.json` runs code or redirects the API before any trust dialog. Source: Check
  Point CVE-2025-59536 (CVSS 8.7, fixed 1.0.111), CVE-2026-21852 (`ANTHROPIC_BASE_URL` key exfil).
  - grep signals: `"SessionStart"` hook with a `command`/shell value in `.claude/settings.json`;
    `enableAllProjectMcpServers: true` or a populated `enabledMcpjsonServers`; an
    `ANTHROPIC_BASE_URL` / `ANTHROPIC_API_URL` / `ANTHROPIC_BEDROCK_BASE_URL` override pointing at
    a non-`anthropic.com` host in committed settings or `env`.
  - readme red-flags: "clone and run", "just open in Claude Code", "no setup".
  - fix: never honor repo-local `SessionStart` hooks or base-URL overrides from an untrusted
    clone; require explicit per-repo trust; pin MCP enablement to an allowlist.

- **`committed-mcp-config-autolaunch`** — high / config. A committed `.mcp.json` /
  `.vscode/mcp.json` / `.cursor/mcp.json` auto-launches a server via `npx`/`uvx`/`docker` on open,
  pulls an unpinned package, or forwards host secrets. Source: CVE-2025-54136 (MCPoison),
  CVE-2025-54135 (CurXecute), CVE-2025-6514 (mcp-remote).
  - grep signals: committed mcp-config with `command: npx|uvx|bunx` + `-y` and no version pin / no
    `@x.y.z`; an `env` map in that file containing `AWS_*` / `GITHUB_TOKEN` / `*_API_KEY` /
    `${env:...}` / `${input:...}` pointed at a non-first-party command; `type: sse|http` `url` to
    an external host.
  - fix: pin server packages by version/digest; do not place secrets in committed mcp-config
    `env`; gate auto-launch behind trust.

- **`ai-agent-ci-untrusted-event-context`** — critical / config. `.github/workflows/*` calls an
  AI-agent action (`claude-code-action`, Gemini CLI, Copilot agent) and interpolates
  `github.event.issue.body` / `pull_request.body` / `comment.body` into the agent step while
  holding write/secret scope. Source: GMO Flatt/RyotaK Jan 2026 (claude-code-action
  `checkWritePermissions` trusted any `*[bot]`, fixed v1.0.94); Microsoft Security Blog June 2026.
  - grep signals: workflow `uses:` an AI-agent action AND a step input references
    `${{ github.event.*.body }}` / `.title` / `.comment.*`; trigger is `issue_comment` / `issues`
    / `pull_request_target`; `permissions: contents: write` or `secrets:` exposed to that job.
  - fix: never pass raw event text as agent instructions; sanitize/quote; drop write+secret scope
    on untrusted-trigger jobs. Pairs with existing `actions-expression-injection-run` (different
    surface: that one is `run:`, this is an agent step).

### P0-2. Rules File Backdoor + cross-tool instruction-file class
The biggest single missing file family. Keyword scan: `cursorrules`, `copilot`, `AGENTS.md`,
`rules file` → **none**. Existing `prompt-injection-hidden-instructions-in-skill` and
`invisible-unicode-in-instructions` cover only the Claude `SKILL.md`/agent surface.

New check in **Claude Plugins, Skills, Hooks & Agents** (or seed the new category in §5).

- **`rules-file-backdoor-cross-tool`** — high / grep. A committed cross-tool instruction file
  carries imperative override/exfiltration language or hidden codepoints. Source: Pillar Security
  (Mar 2025), MITRE ATLAS AML-CS0041.
  - file targets: `.cursorrules`, `.cursor/rules/*.md(c)`, `.github/copilot-instructions.md`,
    `AGENTS.md`, `.windsurfrules`, `.clinerules`, `continue` config (extend the existing
    `CLAUDE.md`/agent sweep to this list).
  - grep signals: imperative override/exfil phrases addressed at the model ("always add",
    "insert", "send env", "ignore previous", "do not mention", "weaken", "disable validation");
    any invisible/non-printing codepoint (reuse `invisible-unicode-in-instructions` byte sweep
    across these files).
  - fix: treat repo-committed instruction files as untrusted; diff-review before the agent
    ingests them.

### P0-3. Modern AI/infra key prefixes the secret regex misses
`hardcoded-api-key-literal` confirmed to cover only `sk-`/`sk-ant-`/AKIA/`ghp_` family. Biggest
2025-2026 leak surge is uncovered. Source: GitGuardian Sprawl 2026 (AI-service leaks +81% YoY);
Supabase `sb_secret_` mandatory for new projects after Nov 1 2025 (non-JWT, full service_role
equivalent, invisible to the JWT-era detector).

Extend existing **Secrets & Credentials** (`hardcoded-api-key-literal` signal list + a new
dedicated check for the opaque-key formats).

- **`secret-modern-key-prefix-sweep`** — critical / grep.
  - grep signals: `sb_secret_` (Supabase secret), `cfat_` / `cfut_` (Cloudflare account/user
    token), `npm_` (npm), `ghr_` (GitHub refresh), `xai-`, `gsk_` (Groq), `hf_` (HuggingFace),
    `r8_` (Replicate); DeepSeek/Perplexity/Mistral/Cohere `sk-` value-shapes in fetch
    headers/fixtures/notebooks.
  - fix: rotate; move to secret store; for Supabase note `sb_secret_` bypasses RLS and must never
    reach the client.

### P0-4. Slopsquatting — imported package absent from lockfile / registry
No hallucinated-dependency check exists (keyword scan: `slopsquat`, `hallucin` → none).
`typosquat-dependency-confusion` matches near-miss spellings of *real* packages; this is fully
fabricated names. Source: Spracklen et al., USENIX Security 2025 (5.2-21.7% hallucination, 58%
recurrence); Aikido `unused-imports` confirmed-malicious npm slopsquat Feb 2026.

Extend **Dependencies & Supply Chain**.

- **`slopsquat-import-not-in-lockfile`** — high / config.
  - signals: an `import`/`require` whose package name has no entry in
    `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml`/`poetry.lock`/hashed `requirements.txt`,
    and/or the name does not resolve on the public registry; the dependency-confusion twist
    (internal-looking name, no private-registry pin, no lockfile resolution); `99.0.0`-style
    inflated version pin (Nesbitt).
  - fix: verify the package exists and is the intended one before install; pin via lockfile;
    reserve internal names on the public registry.

## 3. P1 — strong adds

### P1-1. React2Shell RSC unauthenticated RCE by version pin
critical / config. New (existing `nextjs-middleware-auth-bypass` is CVE-2025-29927, a different
mechanism). Source: CVE-2025-55182 (CVSS 10.0, CISA KEV Dec 5 2025, in-the-wild cryptominer).
- **`nextjs-rsc-react2shell-version-floor`** — config signals: a `next` pin 15.x/16.x below the
  patched floor (or affected 14.3.0-canary.77+), and/or a `react-server-dom-webpack|parcel|turbopack`
  lockfile entry at 19.0.0/19.1.0/19.1.1/19.2.0. Note the second patch round raised the real floor
  to react 19.0.3/19.1.4/19.2.3. `react`/`react-dom` themselves are a weak proxy, not the true
  package; App Router only (Pages Router / 14.x stable / Edge not affected). fix: bump to the
  second-round patched `next`/`react-server-dom-*`.

### P1-2. Server Actions / framework actions are public endpoints
high / trace. Extends `nextjs-middleware-auth-bypass` (which is about middleware-only auth) with
the action-is-a-public-endpoint case. Source: official Astro Actions docs (`blog.like()` callable
at `/_actions/blog.like`), official Next.js security doc ("`'use server'` exposes an endpoint …
always start by validating the current user").
- **`server-action-no-inline-authz`** — trace signals: an exported `'use server'` function or
  Astro/SvelteKit action that mutates data with no session/role check in its first lines; auth
  enforced only by page-level middleware or conditional render. Scope: for Next the action
  inherits page-URL middleware, so fire on guards that are only conditional-render/page-load; for
  Astro/SvelteKit the bypass is unconditional. fix: re-authorize inside every action body.

### P1-3. Astro middleware auth bypass via path-normalization
high / grep. Extends `nextjs-middleware-auth-bypass` (header-specific) with the
canonicalization-mismatch variant, cross-framework. Source: CVE-2025-64765 (CWE-22),
CVE-2025-66202 (double-encoding bypass of the first fix, fixed Astro 5.15.8).
- **`middleware-path-normalization-authz-bypass`** — grep signals: middleware string-comparing
  `url.pathname` (`startsWith('/admin')`, `===`) to gate access, plus `astro < 5.15.8` in
  package.json. Payload that bypasses post-5.15.8-fix is double-encoded `/%2561dmin`. fix:
  authorize on the decoded/canonical path; upgrade Astro.

### P1-4. Lethal trifecta co-located in one agent, egress unconstrained
critical / config. Extends `agent-untrusted-inbound-autonomous-outbound` (two legs as a pair) to
the formal three-leg union + the unconstrained-egress leg. Source: Willison 2025-06-16; OWASP
AST01. Should *reference* the SSRF and injection checks rather than re-detect, to avoid
triple-counting (see merge seam #1).
- **`agent-lethal-trifecta-colocation`** — config signals: one agent/MCP tool list holding all
  three of {private-data read (DB/file/secret tool), untrusted-content read (issue/email/url/web
  reader), external egress (arbitrary-URL fetch, webhook/email send, markdown-image render)} with
  no domain allowlist on the egress leg and no quarantine boundary. fix: break one leg — allowlist
  egress, quarantine untrusted content, or drop the private-data tool.

### P1-5. DNS-rebinding against localhost HTTP/SSE MCP servers
high / config. Distinct from `ssrf-redirect-or-dns-rebind-bypass` (app-code SSRF) and
`mcp-unauthenticated-network-server` (wildcard-CORS/no-auth). Source: CVE-2025-66414 (TS SDK
<1.24.0, CVSS 7.6), CVE-2025-66416 (Python SDK <1.23.0); IBM bulletin.
- **`mcp-localhost-http-dns-rebinding`** — config signals: an MCP StreamableHTTP/SSE transport
  bound to `127.0.0.1`/`localhost` with no `enableDnsRebindingProtection` / `allowedHosts` /
  `allowedOrigins` / Host-header validation and no auth, on a vulnerable SDK version pin. fix:
  enable DNS-rebinding protection / Host allowlist; upgrade SDK.

### P1-6. Full-schema MCP tool poisoning (non-description slots)
high / grep. Extends `mcp-injectable-tool-description` (description/name only) to the other schema
positions. Source: CyberArk "Poison Everywhere" (FSP); OWASP MCP03:2025 as context.
- **`mcp-tool-schema-poison-nondescription`** — grep signals: imperative natural-language text or
  secret-path/side-effect tokens (`ssh`, `id_rsa`, `.env`, `read_file`) appearing in `enum`
  values, `default` values, the `required[]` array, `type` strings, or custom/non-standard schema
  keys — positions that should hold identifiers/enums/types. fix: validate schema fields are pure
  identifiers/enums; lint all slots, not just `description`.

### P1-7. Cross-surface invisible/control-character payload sweep
high / grep. Generalizes `invisible-unicode-in-instructions` (single-file) with the ANSI/0x1B
family and breadth across all MCP tool metadata, manifests, and the rules-file class.
- **`hidden-payload-codepoint-and-ansi-sweep`** — grep signals: ANSI escape `0x1B` / `\033`
  (fg=bg hide, cursor overwrite, OSC-8 link spoof) and non-rendering Unicode (tag chars
  U+E0000-E007F, variation selectors U+E0100-E01EF, zero-width joiners, bidi overrides) in tool
  names/descriptions/enum values, returned-text builders, README, and instruction files. Source:
  Trail of Bits (ANSI-in-MCP 2025), Noma Security (tag/variation-selector smuggling). fix:
  strip/reject control codepoints in any model-read text.

### P1-8. MCP supply chain: import-time-payload / provenance-mismatch server packages
critical / config. Distinct from `npm-postinstall-remote-code` (lifecycle) — this is the
MCP-server-as-dependency provenance case. Source: postmark-mcp npm BCC-exfil (Sept 2025); JFrog 3
PyPI reverse-shell-on-import packages.
- **`mcp-server-package-provenance`** — config signals: an MCP-server package name/owner not
  matching the upstream it claims to mirror; a pinned dependency on a low-reputation MCP package;
  import-time network/shell in the server entrypoint. fix: pin to the verified upstream; review the
  server source before granting tool access.

### P1-9. Supabase Edge Function authless combination
high / config. Sharpens existing `edge-function-verify-jwt-disabled` (already exists,
single-signal) into the dangerous *combination*. Source: Supabase docs ("verify_jwt=false will
allow anyone to invoke"); Feb 2026 field scan (8/9 vibe-coded apps authless).
- Extend `edge-function-verify-jwt-disabled` to fire high/critical only on `(config.toml
  verify_jwt=false OR auth:'none')` **AND** `(SERVICE_ROLE_KEY in function source OR no
  auth.getUser()/declared auth mode)` **AND** wildcard `Access-Control-Allow-Origin:'*'`. A bare
  `verify_jwt=false` is the legitimate signed-webhook pattern (Stripe) and must not alone be
  critical.

### P1-10. Supabase DB-side privesc & SSRF
high / grep. Misses from current DB category: `SECURITY DEFINER` search_path mutability is partly
in `supabase-security-definer-view-or-rpc`, but the pg_net/http SSRF-from-RPC is not. Source:
Supabase advisor lint 0011; Pentestly RPC→http_get SSRF.
- **`supabase-db-side-ssrf-and-search-path`** — grep signals: `SECURITY DEFINER` function without
  `SET search_path` (medium alone); `pg_net`/`http`/`net.http_get`/`http_post` called from a
  `SECURITY DEFINER` RPC granted to `anon`/`authenticated` (high/critical — DB-side SSRF to cloud
  metadata). Split severity accordingly. fix: pin `search_path`; keep network extensions out of
  `public` and off anon-reachable RPCs.

## 4. P2 — worth having

- **`atpa-tool-output-poison`** (trace) — handler builds a return/error string with imperative
  model-directed language or a literal secret path (`~/.ssh/id_rsa`, `.env`, `credentials`).
  High-confidence only on literal secret paths. Source: CyberArk ATPA.
- **`a2a-agent-card-unverified-trust`** (config) — A2A client fetches
  `/.well-known/agent-card.json` (or legacy `/.well-known/agent.json`) over HTTP and routes to its
  `url` without verifying the `signatures`/JWS field; hardcoded peer URLs auto-trusted. Source:
  LevelBlue SpiderLabs; A2A v0.3.
- **`hitl-dialog-forged-from-model-output`** (trace) — custom agent harness renders its
  approval/confirmation text from model output of untrusted content while holding a
  shell/destructive tool. Narrow: only self-built HITL gates. Source: Checkmarx Lies-in-the-Loop.
- **`indirect-injection-in-repo-content`** (grep) — agent-addressing phrases ("AI assistant: do
  X") or hidden HTML comments in README/comments/docstrings/issue-PR text; per-character
  Camo-proxy URL dictionaries. Source: CamoLeak CVE-2025-59145 (CVSS 9.6).
- **`persistent-memory-poison-no-provenance`** (trace) — write path from an untrusted source into
  a durable store (vector/KV/DB/scratchpad) + read-back into prompt with no provenance/sanitization.
  Adjacent to existing `agent-memory-context-poisoning`; the durable cross-session write/read
  dataflow is the new slice. Source: MINJA (NeurIPS 2025), OWASP ASI06:2026.
- **`secrets-in-newer-deploy-config-files`** (config) — committed Cloudflare `.dev.vars`,
  plaintext wrangler `[vars]`, `.vercel/.env*.local` / `.env*.local`, `devcontainer.json`
  containerEnv; value-shaped keys under generic field names in mcp/claude configs. Source:
  GitGuardian 2026 (MCP config = new leak source).
- **`cloudflare-durable-object-idform-name-idor`** (grep/trace) — `idFromName()`/`getByName()`
  built from request-derived input (email/username/seq id) + a DO binding = cross-tenant
  reconstruct. Source: Cloudflare DO ID docs.
- **`baseline-app-ssrf-no-allowlist`** (trace) — user source (`req.query/body/params`, webhook
  field `url`/`callback`/`image_url`) → `fetch`/`axios`/image-loader/PDF renderer with no
  scheme/host allowlist and no private-IP/`169.254.169.254` block. Likely partially in
  `ssrf-user-controlled-fetch`; confirm it covers webhook/callback registration. Source: OWASP SSRF.
- **`expo-rn-mobile-extras`** (grep/trace) — `Linking.addEventListener`/`getInitialURL`/expo-router
  params into navigation or a privileged call with no allowlist; `AsyncStorage.setItem` with
  token/secret/password-named keys instead of SecureStore. EXPO_PUBLIC_/eas.json secret-in-bundle is
  already covered by `secret-in-client-bundle-or-sourcemaps`. Medium. Source: Expo env-var docs.
- **`public-id-as-auth-boundary`** (trace) — client-visible `app_id`/`project_id`/`tenant_id`
  (from manifest/URL/bundle) used as the sole scoping filter or the gate on register/verify/invite
  with no `auth.uid()`/owner/membership check. Source: Base44 bypass (Wiz, July 2025).
- **`next-image-optimizer-permissive-remotepatterns`** (config) — `remotePatterns` hostname
  `**`/protocol-only wildcard or broad `images.domains`; self-hosted `next`/opennextjs-cloudflare
  below patched. Medium (only opennextjs-cloudflare CVE-2025-6087 is High). Source:
  CVE-2025-59471/55173/6087.
- **`mcp-auth-spec-passthrough-missing-aud`** (trace) — HTTP-transport remote MCP server only:
  inbound bearer token forwarded onward and/or no audience/`resource` validation; no
  `/.well-known/oauth-protected-resource`. Gate on HTTP transport or it false-positives on stdio
  servers. Demoted to high+conditional. Source: MCP Auth spec 2025-11-25 (RFC 9728/8707).
- **`pooled-vector-store-no-tenant-filter`** (trace) — similarity search with `topK` and no
  server-side tenant/user metadata filter. Likely already covered by
  `rag-ingestion-poisoning-and-cross-tenant-retrieval` (its signal already names "no
  tenant/namespace filter"); verify before adding, probably redundant.
- **`orchestrator-untrusted-subagent-reentry`** (trace) — raw sub-agent/tool output fed back into
  the planner with no per-message schema validation or provenance tag. Demoted to medium. Source:
  arXiv 2510.17276, OWASP ASI07/ASI08.

## 5. New categories to consider

The P0/P1 adds cluster into one genuinely missing category the current 18 lack:

**"AI Coding-Agent & IDE-Config Trust"** — the committed-config-and-instruction-file surface that
auto-loads into a coding agent. Pulls these out of the overloaded "Claude Plugins, Skills, Hooks &
Agents" bucket and gives the cross-tool (Cursor/Copilot/Windsurf/Cline) checks a home:
- `claude-project-config-clone-open-rce` (P0-1)
- `committed-mcp-config-autolaunch` (P0-1)
- `rules-file-backdoor-cross-tool` (P0-2)
- `ai-agent-ci-untrusted-event-context` (P0-1 — or leave in CI/CD)
- `hidden-payload-codepoint-and-ansi-sweep` (P1-7, shared with MCP metadata)
- `indirect-injection-in-repo-content` (P2)

A second, lighter cluster justifies extending the existing **MCP Server Security** category rather
than a new one: `mcp-localhost-http-dns-rebinding`, `mcp-tool-schema-poison-nondescription`,
`mcp-server-package-provenance`, `atpa-tool-output-poison`, `a2a-agent-card-unverified-trust`. It
already has 20 checks; these fit its scope.

## 6. Out of scope / runtime-only

- **AGENTS.md written at build time from a malicious dependency** (NVIDIA/Codex variant of the
  Rules File Backdoor) — leaves no committed artifact, so a static repo scan cannot see it. The
  committed-file variant (P0-2) is the in-scope half; do not chase the build-time one.
- **Persistent memory poisoning firing weeks later, A2A task interception, orchestration
  control-flow hijack at runtime** — only the static *precursors* (write/read dataflow, unverified
  card fetch, unvalidated re-entry) are detectable. Score the precursor; do not promise to catch
  the live exploit.
- **MCP auth-spec passthrough on stdio servers** — the spec says stdio servers SHOULD NOT follow
  it, so this check must gate on HTTP transport; on the common local/stdio repo it does not apply
  and will false-positive. Treat as conditional, not a broad check.
- **Lies-in-the-Loop against Claude Code's own built-in approval dialog** — a scanned repo does
  not control that dialog. Only self-built HITL gates are in scope.
- **Denial-of-wallet / unbounded token loops** — already covered by
  `denial-of-wallet-unbounded-agent-loops`; no new avenue needed.

## 7. Self-hardening note

git-gud-security runs agents over untrusted repos in `full`/`ultra` mode, so the scanner host is
itself a target of three of the P0 avenues. Two concrete threats and the fix:

- A scanned repo's committed `.claude/settings.json` with a `SessionStart` hook,
  `enableAllProjectMcpServers: true`, or an `ANTHROPIC_BASE_URL` override (CVE-2025-59536 /
  CVE-2026-21852) could execute code or exfiltrate the scanner's own API key the moment the agent
  opens the repo. A committed `.mcp.json` (CVE-2025-54136) could auto-spawn an attacker MCP server
  on the scanner host.
- **Recommendation:** before any `full`/`ultra` run, the workflow should (a) refuse to honor
  repo-local `.claude/settings.json` hooks, base-URL overrides, and
  `enableAllProjectMcpServers`/`enabledMcpjsonServers` from the scanned tree; (b) never auto-launch
  a server from a scanned `.mcp.json`/`.vscode/mcp.json`/`.cursor/mcp.json`; (c) treat these files
  as *findings to read as data*, never as config to load. Run the scanner agent with its own
  pinned settings and an explicit base URL, isolated from the target repo's config precedence. The
  P0-1 checks double as the scanner's own pre-flight: run them against the target *before* the
  agent ingests anything.

## 8. Appendix: dropped candidates

- **Excessive agency / over-broad tool scoping** — every load-bearing claim maps to an existing
  check: `agent-tools-overbroad`, `command-allowed-tools-bash-wildcard` +
  `command-allowed-tools-wildcard`, `settings-json-widens-permissions`. Only missing piece is a
  taxonomy label, not a detection gap. DROP.
- **Missing provenance/quarantine on tool results + rug-pull non-pinning** — both are named live
  checks: `mcp-rug-pull-tool-redefinition` (CVE-2025-54136) and
  `mcp-prompt-injection-via-tool-output` (OWASP MCP06). Re-describes existing checks. DROP.
- **AI-generation provenance as a scan-mode escalation trigger** —
  `vibe-coded-scaffold-insecure-defaults` already keys on "Lovable/Bolt/v0/Replit Agent/Cursor"
  etc. The only differentiator is a scoring-engine behavior change, not a new static signal. DROP.

## 9. Follow-up: re-run the blocked supply-chain-worm finder

The Shai-Hulud / chalk-debug / tj-actions / nx-s1ngularity worm-signature work did not complete.
Targets for the re-run: lifecycle scripts that invoke secret scanners (trufflehog/gitleaks) or
self-publish (`npm publish` inside install), exfil endpoints in install/CI scripts
(webhook.site/pipedream/requestbin/discord/`*.oast.*`), workflows that POST repo secrets to an
external URL, obfuscated `bundle.js` install entrypoints, and abuse of an installed AI CLI to scan
for secrets. Plus the positive hardening controls (npm trusted publishing / OIDC, provenance,
`--ignore-scripts`, minimum-release-age, lockfile-lint).
