export const meta = {
  name: 'ggs-hardening-research',
  description: 'Deep web-grounded research for new security-detection avenues to add to git-gud-security, gap-checked against its 288-check library and adversarially verified',
  phases: [
    { title: 'Find', detail: '8 web-grounded finders, one per security frontier' },
    { title: 'Merge', detail: 'dedup + normalize all candidate avenues into one master list' },
    { title: 'Verify', detail: 'adversarial check per avenue: real? genuine gap? statically detectable? in-scope?' },
    { title: 'Synthesize', detail: 'prioritize survivors into a hardening roadmap with drop-in checks' },
  ],
}

// Coverage map (the existing 288-check library, condensed) is passed via args to avoid escaping.
const COV = (args && args.coverageMap) || '(coverage map missing)'
const TODAY = (args && args.today) || '2026-06-23'

const SCANNER_NATURE =
  'TARGET TOOL: git-gud-security is a STATIC scanner for a repo or a README. It does NOT run the app. ' +
  'Its detection tiers are: readme (phrases/claims in README/docs/manifests), config (manifest/config-file values), ' +
  'grep (deterministic source patterns), trace (model reads code and traces dataflow), adversarial (multi-agent refute). ' +
  'Scope is everything but tuned app-leaning (Supabase / Cloudflare / Next.js / Expo) plus a strong Claude-ecosystem class ' +
  '(skills, plugins, hooks, agents, slash commands, MCP servers). ' +
  'A proposed check is only useful if there is SOME static signal in repo files / config / README that maps to it. ' +
  'A purely runtime-only attack (only observable when the live app is hit) is still admissible ONLY if a static precursor ' +
  'is detectable (e.g. "user-controlled URL reaches fetch with no allowlist"); say so and propose THAT signal.'

const ANTIFAB =
  'ANTI-FABRICATION (hard rule, the tool owner drops findings that are eyeballed or invented): ' +
  'Every avenue MUST cite at least one source you actually retrieved this run via WebSearch/WebFetch. ' +
  'Never invent a CVE id, a date, an incident name, a vendor advisory, or a package name. ' +
  'If you cannot retrieve a real source, either omit the avenue or set evidence kind to "unverified-lead" with a low ' +
  'confidence and say plainly it is unconfirmed. The verify stage will DROP anything whose evidence does not hold, so ' +
  'guessing only wastes the slot.'

const COVERAGE_INSTRUCTION =
  'Below is git-gud-security\'s ENTIRE existing check library, condensed to one line per category (titles only). ' +
  'Your job is to find what is NOT already here, or here only shallowly. For each avenue, classify coverage as: ' +
  'NEW (no existing check addresses it), PARTIAL (a related check exists but misses this variant/depth), or ' +
  'COVERED (already handled — do not propose COVERED items). Name the overlapping existing check when PARTIAL/COVERED.\n\n' +
  '=== EXISTING COVERAGE (18 categories, 288 checks) ===\n' + COV + '\n=== END EXISTING COVERAGE ==='

const TOOLING =
  'TOOLS: WebSearch and WebFetch are your primary instruments — use them heavily. If either is not immediately ' +
  'available, load it first with ToolSearch query "select:WebSearch,WebFetch". Prefer primary sources ' +
  '(CVE/NVD/GHSA records, vendor security advisories, the OWASP project pages, the MCP spec, original research writeups ' +
  'from the disclosing firm). Cross-check at least two sources for any incident or CVE before trusting the details. ' +
  'You MAY use Context7 (resolve-library-id then query-docs) for current framework/library specifics. ' +
  'Date-scope: prioritize developments from 2025 and 2026 (today is ' + TODAY + '). Older items only if still under-covered.'

const FINDER_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['avenues'],
  properties: {
    avenues: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['title', 'summary', 'why_now', 'evidence', 'coverage', 'detectability', 'proposed_category', 'proposed_checks', 'confidence'],
        properties: {
          title: { type: 'string', description: 'short, specific name of the avenue' },
          summary: { type: 'string', description: '2-3 sentences: the attack/weakness and the static signal that betrays it' },
          why_now: { type: 'string', description: 'why this is a live/emerging concern in 2025-2026' },
          evidence: {
            type: 'array', minItems: 1,
            items: {
              type: 'object', additionalProperties: false,
              required: ['kind', 'ref', 'url'],
              properties: {
                kind: { type: 'string', enum: ['cve', 'incident', 'research', 'framework', 'vendor-advisory', 'spec', 'unverified-lead'] },
                ref: { type: 'string', description: 'CVE id / incident name / paper or post title / framework section' },
                date: { type: 'string' },
                url: { type: 'string' },
              },
            },
          },
          coverage: { type: 'string', enum: ['NEW', 'PARTIAL'] },
          overlaps_existing: { type: 'string', description: 'name the closest existing check(s), or "none"' },
          detectability: { type: 'string', enum: ['readme', 'config', 'grep', 'trace', 'adversarial', 'runtime-precursor'] },
          proposed_category: { type: 'string', description: 'existing category to extend, or a proposed new category name' },
          proposed_checks: {
            type: 'array', minItems: 1, maxItems: 4,
            items: {
              type: 'object', additionalProperties: false,
              required: ['title', 'severity', 'detectability', 'fix'],
              properties: {
                title: { type: 'string' },
                severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
                detectability: { type: 'string', enum: ['readme', 'config', 'grep', 'trace', 'adversarial', 'runtime-precursor'] },
                grep_signals: { type: 'array', items: { type: 'string' }, description: 'concrete tokens/patterns to grep, if any' },
                readme_redflags: { type: 'array', items: { type: 'string' }, description: 'README phrases that betray it, if any' },
                example: { type: 'string' },
                fix: { type: 'string' },
              },
            },
          },
          confidence: { type: 'number', description: '0-100 your confidence this is real AND a genuine gap' },
        },
      },
    },
  },
}

const MERGE_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['master', 'dedup_notes', 'seam_notes'],
  properties: {
    master: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        required: ['title', 'frontier', 'summary', 'evidence', 'coverage', 'detectability', 'proposed_category', 'proposed_checks', 'source_finders'],
        properties: {
          title: { type: 'string' },
          frontier: { type: 'string' },
          summary: { type: 'string' },
          why_now: { type: 'string' },
          evidence: { type: 'array', items: { type: 'object', additionalProperties: true } },
          coverage: { type: 'string' },
          overlaps_existing: { type: 'string' },
          detectability: { type: 'string' },
          proposed_category: { type: 'string' },
          proposed_checks: { type: 'array', items: { type: 'object', additionalProperties: true } },
          source_finders: { type: 'array', items: { type: 'string' } },
        },
      },
    },
    dedup_notes: { type: 'string' },
    seam_notes: { type: 'string', description: 'overlaps/seams between frontiers, and any gap no finder covered' },
  },
}

const VERIFY_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['title', 'real_and_accurate', 'gap_confirmed', 'in_scope', 'detectability_final', 'severity_final', 'confidence', 'verdict', 'rationale'],
  properties: {
    title: { type: 'string' },
    real_and_accurate: { type: 'boolean', description: 'is the cited evidence real and described correctly' },
    evidence_check: { type: 'string', description: 'what you confirmed/refuted about the sources' },
    gap_confirmed: { type: 'boolean', description: 'genuinely not already in the existing 288 checks' },
    in_scope: { type: 'boolean', description: 'statically detectable by a repo/README scanner' },
    detectability_final: { type: 'string', enum: ['readme', 'config', 'grep', 'trace', 'adversarial', 'runtime-precursor'] },
    severity_final: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
    confidence: { type: 'number' },
    corrections: { type: 'string', description: 'any factual corrections to the avenue as written' },
    verdict: { type: 'string', enum: ['KEEP', 'DEMOTE', 'DROP'] },
    rationale: { type: 'string' },
  },
}

// ---------------------------------------------------------------- FIND
phase('Find')

const FINDERS = [
  {
    key: 'mcp-second-wave',
    title: 'MCP server security — second wave',
    brief:
      'Find MCP-server security avenues that emerged or matured in 2025-2026 BEYOND what is already covered. ' +
      'Existing coverage already includes: shell-out/eval on model params, SSRF, path confinement, SQL-from-model, ' +
      'deserialization, no-auth port/CORS, confused deputy, OAuth token passthrough/audience confusion, secrets returned ' +
      'to context, indirect prompt injection via returned content, injected instructions in tool description/name, rug-pull ' +
      '(tool mutates after approval), tool shadowing via generic names, missing param schema, destructive action with no ' +
      'human gate, TLS verify disabled, unbounded output, trusted-stdio assumption, sampling/elicitation exfil. ' +
      'Look HARDER for: full-schema poisoning (poisoning beyond description — type/enum/required/default fields); ' +
      'advanced tool-poisoning via tool OUTPUT or ERROR messages (ATPA); ANSI/control-character/invisible-unicode payloads ' +
      'in tool metadata; the MCP authorization spec changes (Protected Resource Metadata RFC 9728, Resource Indicators ' +
      'RFC 8707, PKCE, audience binding) and what a server missing them looks like statically; DNS-rebinding / "0.0.0.0-day" ' +
      'against locally-bound HTTP/SSE MCP servers; the official MCP Registry and npm/PyPI-published MCP servers as a supply ' +
      'chain (malicious or typosquatted server packages); tool-preference / ranking manipulation; consent/elicitation ' +
      'phishing; cross-server "line jumping". Cite real research (e.g. Invariant Labs, Cisco, Trail of Bits, Simon Willison, ' +
      'the MCP spec changelog) and any CVEs/GHSAs in real MCP server packages.',
  },
  {
    key: 'agentic-taxonomy',
    title: 'Agentic & multi-agent threat taxonomy',
    brief:
      'Mine the formal agentic-security frameworks for threat classes git-gud-security can detect STATICALLY in an agent ' +
      'repo. Sources: OWASP "Agentic AI - Threats and Mitigations" / the Agentic Security Initiative, OWASP Multi-Agentic ' +
      'threat-modeling (MAESTRO), the OWASP Agentic AI Top 10 if published, CSA/MITRE ATLAS agentic entries, and Simon ' +
      'Willison\'s "lethal trifecta" (private data + untrusted content + exfiltration in one agent). Existing coverage ' +
      'already has: agent reads attacker inbound while holding autonomous write/send tools, memory poisoning, RAG/vector ' +
      'semantic IDOR, denial-of-wallet, LLM-as-security-gate, markdown-image exfil, insecure output handling. ' +
      'Find what is MISSING: the lethal-trifecta as an architecture-level check (all three capabilities co-located with no ' +
      'isolation); agent identity/impersonation & inter-agent trust (A2A / agent-to-agent protocol, agent cards); ' +
      'goal/intent/instruction manipulation; tool-misuse & excessive-agency scoping (agent granted more tools/scopes than ' +
      'its task needs); human-in-the-loop bypass or approval-fatigue exploitation; cascading failures across sub-agents; ' +
      'unsafe agent-to-agent message passing; missing provenance/quarantine on tool results before they re-enter the loop. ' +
      'For each, give the concrete repo/config signal a static scanner could match.',
  },
  {
    key: 'ai-coding-agents',
    title: 'AI coding agents / IDE / Claude Code attack surface',
    brief:
      'Research attacks that target AI coding assistants and their config, which a repo scanner can flag. Existing coverage ' +
      'has hooks/skills exfil, curl|bash, $CLAUDE_ENV_FILE, hidden/unicode instructions in SKILL.md, Bash(*) grants, ' +
      'settings auto-approve, self-rewriting agent files, messaging-driven shell. ' +
      'Find what is MISSING, especially: the "Rules File Backdoor" class — malicious or injected instructions in agent ' +
      'rules/instruction files that the IDE/agent auto-loads (.cursorrules, .cursor/rules, .github/copilot-instructions.md, ' +
      'AGENTS.md, CLAUDE.md, .windsurfrules, .clinerules, continue config) including hidden-unicode variants; the GitHub ' +
      'Copilot "CamoLeak" image-proxy exfiltration; the Amazon Q VS Code extension malicious-commit wiper incident; ' +
      'committed mcp.json / .mcp.json / .vscode/mcp.json / .cursor/mcp.json that auto-loads an untrusted or secret-forwarding ' +
      'MCP server when the repo is opened; indirect prompt injection planted in ordinary repo content (README, code comments, ' +
      'issue/PR text, test fixtures) that an agent reads and obeys; Anthropic Agent Skills packaging/distribution risks. ' +
      'IMPORTANT self-relevance: git-gud-security itself runs agents over untrusted repos in full/ultra mode, so note which ' +
      'of these also threaten the SCANNER and deserve a defensive note. Cite the disclosing firms (Pillar Security, ' +
      'Legit Security, HiddenLayer, Embrace The Red, etc.) and any CVEs.',
  },
  {
    key: 'supply-chain-campaigns',
    title: 'Supply chain — 2025-2026 worms & campaigns',
    brief:
      'Catalog the major 2025-2026 software-supply-chain attacks and turn their mechanics into detection signatures. ' +
      'Real campaigns to verify and mine: the Shai-Hulud self-replicating npm worm (Sept 2025; and any 2nd wave); the ' +
      'chalk/debug et al. maintainer phishing compromise (qix account, Sept 2025); tj-actions/changed-files compromise ' +
      '(CVE-2025-30066) and reviewdog; the nx / s1ngularity attack (Aug 2025) notable for abusing installed AI CLIs ' +
      '(claude/gemini/q) to hunt secrets; GhostAction; PyPI campaigns. Existing coverage has: postinstall fetching/running ' +
      'remote code, README curl|bash, no lockfile, unpinned actions/deps, known-CVE deps, typosquat/dep-confusion, ' +
      'committed publish tokens, provenance/signatures absent, build executes untrusted plugins. ' +
      'Find the MISSING signatures: lifecycle scripts that invoke secret scanners (trufflehog/gitleaks) or self-publish ' +
      '(npm publish inside install/postinstall = worm tell); exfil endpoints in install/CI scripts (webhook.site, ' +
      'pipedream, requestbin, discord webhooks, *.oast.*); workflows that POST repo secrets to an external URL; obfuscated ' +
      'bundle.js as an install entrypoint; abuse of an installed AI CLI to scan for secrets; npm manifest confusion; ' +
      'missing trusted-publishing/OIDC + the positive hardening (npm provenance, Sigstore, minimum-release-age, ' +
      '`--ignore-scripts`, lockfile-lint). Give grep-able tokens for each.',
  },
  {
    key: 'slopsquat-aicode',
    title: 'Slopsquatting & AI-generated-code weakness patterns',
    brief:
      'Two linked frontiers. (1) SLOPSQUATTING: attackers pre-register package names that LLM code generators hallucinate, ' +
      'so a vibe-coded import resolves to attacker code. Distinct from typosquatting (already covered). Find the research ' +
      'quantifying hallucinated-package rates and any real registered-hallucination incidents; propose a static signal ' +
      '(imported/required package not in the lockfile or registry, or a dependency first published very recently with one ' +
      'maintainer that a generated project depends on). (2) AI-SCAFFOLD MASS EXPOSURE: research on insecure defaults from ' +
      'Lovable/Bolt/v0/Base44/Replit-generated apps leaking data (e.g. the Lovable Supabase RLS-off exposure reporting, ' +
      '"VibeScamming"). Existing coverage already flags "AI-scaffold insecure default config and auth stubs left in" ' +
      'generically and the RLS checks — so go for the SPECIFIC, named, current variants and any systematic study of ' +
      'vulnerability rates in AI-generated code. Cite the studies/reports (Socket, Trend Micro, academic papers, the ' +
      'original disclosure posts).',
  },
  {
    key: 'web-cloud-cves',
    title: 'Web/cloud platform emerging CVEs & patterns',
    brief:
      'Find concrete, dated, app-leaning platform vulns from 2025-2026 that a static scanner can flag, in the stacks this ' +
      'tool targets (Next.js, React, Supabase/Postgres, Cloudflare, Firebase, common meta-frameworks). Existing coverage ' +
      'already has the Next.js middleware-auth bypass (CVE-2025-29927), RLS/Firebase basics, SSRF, CORS, headers. ' +
      'Verify and mine: Next.js AFTER 29927 — cache-poisoning / response-queue CVEs (e.g. CVE-2025-49826, CVE-2025-49005), ' +
      'image-optimization SSRF, and React Server Actions being public unauthenticated endpoints (auth must be re-checked ' +
      'inside every action) plus React taint APIs; SvelteKit/Astro/Remix/Nuxt form-action or server-endpoint auth gaps; ' +
      'Supabase specifics — SECURITY DEFINER functions with a mutable/empty search_path (privilege escalation), pg_net / ' +
      'http extension SSRF from the database, the new Supabase API key format (sb_publishable_... vs sb_secret_...) and ' +
      'detecting a leaked secret key, Edge Function verify_jwt nuances; Cloudflare Workers — secrets in plaintext vars vs ' +
      'secret bindings, over-broad service bindings, public KV/D1/R2 exposure, wrangler .dev.vars committed. ' +
      'Give the file/config/grep signal for each and a real CVE/advisory where one exists.',
  },
  {
    key: 'secrets-nhi',
    title: 'Secrets & non-human-identity evolution',
    brief:
      'Audit what NEW secret formats and identity risks a 2026 scanner must catch. You MAY read the tool\'s current ' +
      'patterns at C:\\Users\\atk67\\Documents\\git-gud-security\\scripts\\patterns.json and scripts\\scan.py to see exactly ' +
      'which secret formats it already matches, then report the CONCRETE missing ones. Cover: modern provider key prefixes ' +
      '(e.g. Anthropic sk-ant-, OpenAI sk-proj- / project keys, Google AI, xAI xai-, Groq gsk_, Mistral, Cohere, ' +
      'HuggingFace hf_, Replicate r8_, fine-grained GitHub github_pat_, GitHub OAuth gho_/ghu_/ghs_, Supabase sb_secret_, ' +
      'Vercel, Cloudflare, Slack xoxb-/xoxp-, Stripe rk_/sk_live_, Twilio, SendGrid SG., Doppler, etc.) — confirm current ' +
      'real formats. Then the broader theme: Non-Human Identity (NHI) sprawl and long-lived machine credentials as the ' +
      'dominant 2025 secrets story; OAuth app over-scoping; secrets in new locations a scanner might miss (.dev.vars, ' +
      'wrangler env, vercel .env.local, .mcp.json env blocks, devcontainer, .npmrc //registry _authToken). Existing ' +
      'coverage already has the generic secret/.env/history checks and "long-lived publish tokens". Propose specific new ' +
      'secret-format patterns and NHI-hygiene checks. Cite the format sources (provider docs / Context7) and the NHI trend ' +
      'research (GitGuardian/Truffle/Wiz state-of-secrets reports).',
  },
  {
    key: 'llm-defense-controls',
    title: 'Prompt-injection defenses & LLM-app hardening controls',
    brief:
      'This frontier is about ABSENCE-OF-DEFENSE checks (positive controls) rather than bug signatures: an AI/LLM/agent app ' +
      'that ships without a known mitigation. Ground in the OWASP LLM Top 10 (2025 edition) — confirm the current list and ' +
      'the newer entries (System Prompt Leakage LLM07, Vector & Embedding Weaknesses LLM08, Unbounded Consumption LLM10, ' +
      'Excessive Agency LLM06, Misinformation LLM09) — and current defense research: prompt-injection mitigation patterns ' +
      '(spotlighting/delimiting, data-vs-instruction separation, the dual-LLM and CaMeL capability patterns from Google ' +
      'DeepMind / Simon Willison, output allow-listing/constraining, deterministic policy gates instead of LLM-as-judge for ' +
      'authz, signed/pinned tool manifests, quarantining tool output). Existing coverage already flags LLM-as-security-gate, ' +
      'insecure output handling, denial-of-wallet, system-prompt/secret leakage, RAG poisoning. ' +
      'Propose checks of the form "AI app does X with untrusted content but implements NO defense Y", with the static signal ' +
      '(e.g. user/tool content concatenated directly into the system prompt with no delimiter/segmentation; retrieval ' +
      'results fed to a tool-calling loop with no allow-list on actions; vector store queried without a per-tenant filter). ' +
      'Be honest that some of these are trace-tier and soft; mark detectability accurately.',
  },
]

const finderResults = await parallel(FINDERS.map((f) => () =>
  agent(
    'You are a senior application-security + AI-security researcher hunting NEW detection avenues for a security scanner.\n\n' +
    'FRONTIER: ' + f.title + '\n\n' + f.brief + '\n\n' +
    SCANNER_NATURE + '\n\n' + COVERAGE_INSTRUCTION + '\n\n' + TOOLING + '\n\n' + ANTIFAB + '\n\n' +
    'Return 3-7 high-quality avenues (quality over quantity). For each, fill the schema: a tight summary, why it is live ' +
    'now, real cited evidence, NEW-vs-PARTIAL coverage classification naming the closest existing check, the right ' +
    'detectability tier, and 1-4 concrete proposed checks with grep signals / README red-flags / a fix where applicable. ' +
    'Skip anything already COVERED. Your final message is the structured object only.',
    { label: 'find:' + f.key, phase: 'Find', agentType: 'general-purpose', schema: FINDER_SCHEMA }
  ).then((r) => ({ key: f.key, title: f.title, avenues: (r && r.avenues) || [] }))
))

const finders = finderResults.filter(Boolean)
const rawCount = finders.reduce((n, fr) => n + fr.avenues.length, 0)
log('Find done: ' + finders.length + '/8 finders returned, ' + rawCount + ' raw candidate avenues')

// ---------------------------------------------------------------- MERGE
phase('Merge')

const mergeInput = finders.map((fr) =>
  '## FINDER: ' + fr.key + ' (' + fr.title + ')\n' +
  fr.avenues.map((a, i) =>
    '- [' + fr.key + '#' + (i + 1) + '] ' + a.title + ' | coverage=' + a.coverage +
    ' | detect=' + a.detectability + ' | cat=' + a.proposed_category +
    '\n    summary: ' + a.summary +
    '\n    why_now: ' + a.why_now +
    '\n    overlaps: ' + (a.overlaps_existing || 'none') +
    '\n    evidence: ' + (a.evidence || []).map((e) => e.kind + ':' + e.ref + (e.url ? ' <' + e.url + '>' : '')).join(' ; ') +
    '\n    proposed_checks: ' + (a.proposed_checks || []).map((c) => '[' + c.severity + '/' + c.detectability + '] ' + c.title).join(' | ')
  ).join('\n')
).join('\n\n')

const merged = await agent(
  'You are consolidating candidate security-detection avenues from 8 parallel finders into ONE clean master list for a ' +
  'static repo/README scanner (git-gud-security).\n\n' + SCANNER_NATURE + '\n\n' +
  'Here are all raw candidates:\n\n' + mergeInput + '\n\n' +
  'Do the following:\n' +
  '1. DEDUP: merge avenues that are the same idea under different names (keep the clearest title, union their evidence and ' +
  'proposed checks, list which finders contributed in source_finders).\n' +
  '2. NORMALIZE: keep each avenue\'s strongest 1-4 proposed checks; carry detectability, proposed_category, evidence.\n' +
  '3. PRUNE obvious non-gaps: if a candidate is plainly already in the existing library, drop it and note why in dedup_notes.\n' +
  '4. SEAM CHECK: in seam_notes, call out overlaps between frontiers AND any attack surface NONE of the finders covered ' +
  'that you think a 2026 scanner still needs (you may add it to master as a NEW avenue with evidence kind unverified-lead ' +
  'if you cannot cite it — verify stage will test it).\n\n' +
  'Aim for roughly 18-30 deduplicated avenues. Return the structured object only.',
  { label: 'merge', phase: 'Merge', agentType: 'general-purpose', schema: MERGE_SCHEMA }
)

const master = (merged && merged.master) || []
log('Merge done: ' + master.length + ' deduplicated avenues; verifying each adversarially')

// ---------------------------------------------------------------- VERIFY
phase('Verify')

const verdicts = await parallel(master.map((a, idx) => () =>
  agent(
    'You are an adversarial verifier. Be skeptical: default to DROP unless the avenue holds up on all four tests.\n\n' +
    'AVENUE #' + (idx + 1) + ': ' + a.title + '\n' +
    'summary: ' + a.summary + '\n' +
    'claimed coverage: ' + a.coverage + ' | overlaps: ' + (a.overlaps_existing || 'none') + '\n' +
    'detectability: ' + a.detectability + '\n' +
    'evidence: ' + (a.evidence || []).map((e) => (e.kind || '?') + ':' + (e.ref || '?') + (e.url ? ' <' + e.url + '>' : '')).join(' ; ') + '\n' +
    'proposed checks: ' + (a.proposed_checks || []).map((c) => '[' + c.severity + '/' + c.detectability + '] ' + c.title).join(' | ') + '\n\n' +
    'FOUR TESTS:\n' +
    '1. REAL & ACCURATE: Use WebSearch/WebFetch to confirm the cited CVE/incident/research actually exists and is described ' +
    'correctly. If a CVE id, date, package name, or incident is wrong or unfindable, that is a fail — note the correction. ' +
    'An avenue resting only on an "unverified-lead" that you also cannot confirm fails this test.\n' +
    '2. GENUINE GAP: Re-read the existing coverage and confirm this is NOT already covered. If a listed check already ' +
    'handles it, set gap_confirmed false.\n' +
    '3. IN SCOPE / STATICALLY DETECTABLE: Is there a real static signal in repo files / config / README that maps to a ' +
    'check? If it is only observable against a live running app with no static precursor, set in_scope false.\n' +
    '4. SEVERITY & TIER SANITY: Pick the correct final severity and detectability tier; demote inflated ones.\n\n' +
    SCANNER_NATURE + '\n\n' + COVERAGE_INSTRUCTION + '\n\n' + TOOLING + '\n\n' +
    'Verdict rules: KEEP if all four pass; DEMOTE if real+gap+in-scope but the avenue was overstated (lower severity, ' +
    'narrower claim, or weaker detectability) — say how; DROP if it fails REAL, GAP, or IN-SCOPE. ' +
    'Return the structured object only.',
    { label: 'verify#' + (idx + 1), phase: 'Verify', agentType: 'general-purpose', schema: VERIFY_SCHEMA }
  ).then((v) => ({ avenue: a, verdict: v }))
))

const checked = verdicts.filter(Boolean).filter((x) => x.verdict)
const kept = checked.filter((x) => x.verdict.verdict === 'KEEP' || x.verdict.verdict === 'DEMOTE')
const dropped = checked.filter((x) => x.verdict.verdict === 'DROP')
log('Verify done: ' + kept.length + ' survive (' +
    checked.filter((x) => x.verdict.verdict === 'KEEP').length + ' KEEP, ' +
    checked.filter((x) => x.verdict.verdict === 'DEMOTE').length + ' DEMOTE), ' + dropped.length + ' dropped')

// ---------------------------------------------------------------- SYNTHESIZE
phase('Synthesize')

const survivorBlock = kept.map((x, i) => {
  const a = x.avenue, v = x.verdict
  return '### ' + (i + 1) + '. ' + a.title + '  [' + v.verdict + ']\n' +
    'frontier: ' + (a.frontier || '') + ' | proposed_category: ' + a.proposed_category + '\n' +
    'final severity: ' + v.severity_final + ' | final detectability: ' + v.detectability_final + ' | confidence: ' + v.confidence + '\n' +
    'summary: ' + a.summary + '\n' +
    'why_now: ' + (a.why_now || '') + '\n' +
    'coverage vs existing: ' + a.coverage + ' (overlaps: ' + (a.overlaps_existing || 'none') + ')\n' +
    'corrections from verify: ' + (v.corrections || 'none') + '\n' +
    'evidence: ' + (a.evidence || []).map((e) => (e.kind || '?') + ':' + (e.ref || '?') + (e.url ? ' <' + e.url + '>' : '')).join(' ; ') + '\n' +
    'proposed checks:\n' + (a.proposed_checks || []).map((c) =>
      '  - [' + c.severity + '/' + c.detectability + '] ' + c.title +
      (c.grep_signals && c.grep_signals.length ? '\n      grep: ' + c.grep_signals.join(' , ') : '') +
      (c.readme_redflags && c.readme_redflags.length ? '\n      redflag: ' + c.readme_redflags.join(' , ') : '') +
      (c.fix ? '\n      fix: ' + c.fix : '')
    ).join('\n')
}).join('\n\n')

const droppedBlock = dropped.map((x) => '- ' + x.avenue.title + ' — ' + (x.verdict.rationale || 'dropped')).join('\n')

const report = await agent(
  'You are writing the final hardening-research deliverable for git-gud-security: a roadmap of NEW security-detection ' +
  'avenues to add to its 288-check library. The audience is the tool\'s author (a solo builder who hates fluff, AI cadence, ' +
  'em-dashes, and fabrication; wants a real prioritized recommendation, not a menu).\n\n' + SCANNER_NATURE + '\n\n' +
  'VERIFIED SURVIVING AVENUES (already adversarially checked; corrections applied):\n\n' + survivorBlock + '\n\n' +
  'DROPPED (for the appendix, one line each):\n' + droppedBlock + '\n\n' +
  'MERGE SEAM NOTES: ' + ((merged && merged.seam_notes) || 'none') + '\n\n' +
  'Write a tight markdown report with these sections:\n' +
  '1. **Bottom line** — 3-5 sentences: the highest-value avenues to add and the one-sentence theme of where the library ' +
  'is now blind.\n' +
  '2. **P0 — add now** — the avenues with the best (impact x fit-to-scope x ease-of-detection). For each: one-line ' +
  'description, where it slots (extend existing category X or new category Y), detectability tier, severity, and the ' +
  'concrete check(s) ready to drop into checks.data.json (title + grep signals / readme red-flags + fix).\n' +
  '3. **P1 — strong adds** — same format, slightly lower priority.\n' +
  '4. **P2 — worth having** — terse list, title + one line each.\n' +
  '5. **New categories to consider** — if several avenues cluster into a category the library lacks (e.g. an ' +
  '"Agent rules-file & IDE-config trust" or "AI coding-agent" category), name it and list its checks.\n' +
  '6. **Out of scope / runtime-only** — avenues that are real but a static scanner cannot meaningfully catch; say why, so ' +
  'the author does not chase them.\n' +
  '7. **Self-hardening note** — anything that threatens git-gud-security ITSELF (its agents read untrusted repos in ' +
  'full/ultra mode); concrete defensive recommendation.\n' +
  '8. **Appendix: dropped candidates** — the one-liners above.\n\n' +
  'Rules: cite the real source (CVE/incident/framework) inline where it backs a recommendation. No em-dashes, no ' +
  '"not X but Y", no three-beat filler, no emoji, no flattery. Terse and concrete. Every proposed check must name a static ' +
  'signal. Return ONLY the markdown report.',
  { label: 'synthesize', phase: 'Synthesize', agentType: 'general-purpose' }
)

return {
  counts: {
    finders: finders.length,
    rawAvenues: rawCount,
    merged: master.length,
    kept: kept.length,
    dropped: dropped.length,
  },
  report: report,
}
