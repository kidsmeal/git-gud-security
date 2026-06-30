export const meta = {
  name: 'ggs-writable-trust-research',
  description: 'Research the writable-data-trust vulnerability class (the Supabase user_metadata bug and its siblings) for new git-gud-security checks, web-grounded and adversarially verified',
  phases: [
    { title: 'Find', detail: '6 web-grounded finders, one per framework family of the invariant' },
    { title: 'Merge', detail: 'dedup + normalize candidate avenues into one master list' },
    { title: 'Verify', detail: 'adversarial 4-test check per avenue: real? genuine gap? statically detectable? severity sane?' },
    { title: 'Synthesize', detail: 'prioritized roadmap of drop-in checks (patterns.json + checks.data.json ready)' },
  ],
}

const COVERAGE_FALLBACK = `## Secrets & Credentials (secrets-and-credentials)
  - service-role-key-in-client: Service/admin key shipped to the client (RLS bypass)
  - secret-behind-public-env-prefix: Private secret wrapped in a public env prefix
  - secret-in-client-bundle-or-sourcemaps: Secret inlined into the built JS bundle or leaked via source maps
  - safe-public-key-misflagged: Confusing safe-to-expose keys with secret keys
  - secret-modern-key-prefix-sweep: Modern AI/infra API key format committed (newer provider prefixes)
## Auth, Access Control & Account Lifecycle (authn-authz-access-control)
  - no-authz-on-endpoint: API endpoint / route handler with no authentication check
  - idor-object-level-authz: IDOR: object accessed by client-supplied id with no ownership check
  - trust-client-supplied-identity: Trusting a client-supplied user_id / role / tenant instead of the session
  - mass-assignment-role: Mass assignment / over-posting lets client set role, isAdmin, plan
  - authz-only-in-frontend: Authorization enforced only in the frontend (hidden UI, open API)
  - missing-role-check-priv-esc: Authenticated-but-not-authorized: any logged-in user can do admin actions
  - broken-multi-tenant-isolation: Missing tenant scoping (cross-tenant data access)
  - default-allow-authz: Default-allow authorization (fails open)
  - jwt-decode-not-verify: JWT decoded but signature never verified
  - jwt-alg-none-or-confusion: JWT accepts alg=none or no algorithm allowlist
  - jwt-no-expiry-validation: JWT/session token with no expiry or no expiry validation
  - oauth-state-redirect-token-validation: OAuth/SSO flow missing state, open redirect_uri, or unverified id_token
  - nextjs-middleware-auth-bypass: Auth enforced only in Next.js middleware (CVE-2025-29927 / header spoof)
  - magic-link-otp-replay-no-binding: Magic-link / email-OTP replayable, multi-use, or not bound to context
  - signup-no-email-verification-impersonation: Signup with no email verification (impersonation/unverified-trust)
  - server-action-no-inline-authz: Server Action / framework action mutates with no inline authorization
  - middleware-path-normalization-authz-bypass: Middleware authorization bypassable via path normalization / encoding
  - public-id-as-auth-boundary: Client-visible app/project/tenant id used as the auth boundary
  - getsession-unverified-serverside: Unverified client session used for server-side auth decisions
## Database, RLS & Cloud Config (datastore-rls-and-cloud-config)
  - supabase-rls-disabled-public-table: Table in PostgREST-exposed schema with RLS disabled
  - supabase-rls-policy-using-true: RLS policy with USING (true) / WITH CHECK (true) on sensitive table
  - supabase-anon-write-privilege-billing: anon/authenticated INSERT/UPDATE on privilege or billing tables
  - supabase-security-definer-view-or-rpc: SECURITY DEFINER view/RPC bypasses RLS or lacks internal authz
  - supabase-realtime-or-anon-auth-gap: Realtime publication streams an RLS-off table, or anon satisfies 'authenticated'
  - firebase-rules-open-or-auth-only: Firebase/Firestore/RTDB/Storage rules open or auth-presence-only
  - firebase-admin-sdk-in-client: Firebase Admin SDK / service account used client-side
  - firebase-no-appcheck: No Firebase App Check / open client SDK enabling rule brute-force & abuse
  - edge-function-verify-jwt-disabled: Edge/serverless function with verify_jwt disabled and no internal auth
  - supabase-db-side-ssrf-and-search-path: Supabase DB-side SSRF (pg_net/http) and mutable SECURITY DEFINER search_path
  - cloudflare-do-idfromname-idor: Durable Object addressed by request-derived idFromName/getByName (cross-tenant IDOR)
  - rls-policy-user-metadata-bypass: RLS policy references user-writable metadata (trivially bypassable) [SEED BUG, COVERED]
  - user-metadata-authz-client: Authorization decision gated on user-writable user_metadata, app code [SEED BUG, COVERED]
## Business Logic, Payments, Abuse & Rate Limiting (business-logic-abuse-ratelimit)
  - business-logic-price-tampering-and-double-spend: client-supplied price/amount, negative qty, coupon abuse, TOCTOU
  - rate-limit-bypass-trusted-header-or-in-memory: Rate limiter trusts client IP header, or in-memory counter resets
  - fulfill-on-client-redirect-not-webhook: Order fulfilled on client success-redirect instead of verified webhook
  - refund-amount-or-target-client-controlled: Refund amount/target/eligibility client-controlled
## Mobile, Privacy & Vibe-Coded Defaults (mobile-and-privacy)
  - vibe-coded-scaffold-insecure-defaults: AI-scaffold (Lovable/Bolt/v0/Replit/Cursor) insecure default config and auth stubs
  - tokens-in-insecure-local-storage: Auth tokens / secrets in AsyncStorage / SharedPreferences / NSUserDefaults
## AI / LLM / Agent App Security (ai-llm-agent-security)
  - llm-as-judge-authorization-bypass: LLM used as a security gate bypassable by prompt injection`

const COV = (args && args.coverageMap) || COVERAGE_FALLBACK
const TODAY = (args && args.today) || '2026-06-30'

const INVARIANT =
  'THE VULNERABILITY CLASS UNDER STUDY (the "writable-data-trust" invariant). The seed bug: Supabase code does ' +
  '`if (user.user_metadata.role === "admin")`, but user_metadata is end-user-writable via supabase.auth.updateUser() ' +
  '(PUT /auth/v1/user), so any user self-promotes to admin. The class generalizes to ANY case with all four properties: ' +
  '(1) the framework draws a writable-vs-readonly (or verified-vs-unverified) split that developers routinely conflate; ' +
  '(2) a trust / authorization / identity / entitlement decision is keyed on the WRONG (attacker-controllable) side of that split; ' +
  '(3) the insecure path throws NO error and works in dev, so it looks identical to the secure version; ' +
  '(4) a STATIC signal in repo source / config / README betrays it (a token adjacent to a trust sink). ' +
  'You are hunting siblings of the seed bug across frameworks, NOT generic authz bugs. The thing that makes it this class is ' +
  'that the trusted datum is writable/forgeable BY FRAMEWORK DEFAULT and the dev did not realize it.'

const SCANNER_NATURE =
  'TARGET TOOL: git-gud-security is a STATIC scanner for a repo or a README. It does NOT run the app. Detection tiers: ' +
  'readme (phrases in README/docs/manifests), config (manifest/config values), grep (deterministic source patterns), ' +
  'trace (model reads code and traces dataflow), adversarial (multi-agent refute). A proposed check is only useful if there ' +
  'is SOME static signal in repo files / config / README that maps to it. A purely runtime-only behavior is admissible ONLY ' +
  'if a static precursor is detectable; if so, name THAT signal. Prefer grep/config tiers (a concrete token) where possible.'

const ANTIFAB =
  'ANTI-FABRICATION (hard rule, the tool owner drops anything eyeballed or invented): every avenue MUST cite at least one ' +
  'source you actually retrieved this run via WebSearch/WebFetch, ideally the vendor doc page that documents the ' +
  'writable-vs-readonly split. Never invent a CVE id, date, incident name, advisory, or package name. If you cannot retrieve ' +
  'a real source, set evidence kind to "unverified-lead" with low confidence and say so; the verify stage DROPs unconfirmed ' +
  'evidence, so guessing only wastes the slot.'

const COVERAGE_INSTRUCTION =
  'Below is the RELEVANT slice of git-gud-security\'s existing check library (auth, RLS/BaaS, secrets-to-client, ' +
  'request-trust, AI-scaffold, AI/agent). Classify each avenue as NEW (nothing addresses it), PARTIAL (a related check ' +
  'exists but misses this variant/depth), or COVERED (already handled — do NOT propose COVERED items). Name the overlapping ' +
  'check id for PARTIAL/COVERED. Note: `user-metadata-authz-client` and `rls-policy-user-metadata-bypass` are the seed bug ' +
  'itself and are already covered; find its SIBLINGS.\n\n=== EXISTING COVERAGE (relevant categories) ===\n' + COV +
  '\n=== END EXISTING COVERAGE ==='

const TOOLING =
  'TOOLS: WebSearch and WebFetch are your primary instruments. If unavailable, load them first with ToolSearch query ' +
  '"select:WebSearch,WebFetch". For each framework, FETCH the vendor doc page that states which fields are user-writable vs ' +
  'server-only (e.g. Supabase user_metadata vs app_metadata; Auth0 user_metadata vs app_metadata; Clerk publicMetadata vs ' +
  'privateMetadata vs unsafeMetadata; Firebase custom claims vs Firestore profile docs; Cognito mutable custom: attributes). ' +
  'Cross-check incidents/CVEs against two sources. Date-scope: prioritize 2024-2026 (today is ' + TODAY + '). ' +
  'You MAY use Context7 (resolve-library-id then query-docs) for current framework specifics.'

const FINDER_SCHEMA = {
  type: 'object', additionalProperties: false, required: ['avenues'],
  properties: {
    avenues: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        required: ['title', 'summary', 'writable_field', 'safe_field', 'why_silent', 'evidence', 'coverage', 'detectability', 'proposed_category', 'proposed_checks', 'confidence'],
        properties: {
          title: { type: 'string', description: 'short specific name' },
          summary: { type: 'string', description: '2-3 sentences: the trust sink, the writable datum, the exploit' },
          writable_field: { type: 'string', description: 'the attacker-writable/forgeable datum being trusted' },
          safe_field: { type: 'string', description: 'the server-only/verified field that SHOULD have been used' },
          why_silent: { type: 'string', description: 'why it throws no error and passes in dev' },
          why_now: { type: 'string', description: 'why live in 2024-2026 (optional but preferred)' },
          evidence: {
            type: 'array', minItems: 1,
            items: {
              type: 'object', additionalProperties: false, required: ['kind', 'ref', 'url'],
              properties: {
                kind: { type: 'string', enum: ['vendor-doc', 'cve', 'incident', 'research', 'framework', 'spec', 'unverified-lead'] },
                ref: { type: 'string' }, date: { type: 'string' }, url: { type: 'string' },
              },
            },
          },
          coverage: { type: 'string', enum: ['NEW', 'PARTIAL'] },
          overlaps_existing: { type: 'string', description: 'closest existing check id(s), or "none"' },
          detectability: { type: 'string', enum: ['readme', 'config', 'grep', 'trace', 'adversarial', 'runtime-precursor'] },
          proposed_category: { type: 'string' },
          proposed_checks: {
            type: 'array', minItems: 1, maxItems: 4,
            items: {
              type: 'object', additionalProperties: false, required: ['title', 'severity', 'detectability', 'fix'],
              properties: {
                title: { type: 'string' },
                severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
                detectability: { type: 'string', enum: ['readme', 'config', 'grep', 'trace', 'adversarial', 'runtime-precursor'] },
                grep_signals: { type: 'array', items: { type: 'string' }, description: 'concrete regex/tokens to grep, with the include file-extensions' },
                readme_redflags: { type: 'array', items: { type: 'string' } },
                example: { type: 'string' },
                fix: { type: 'string' },
              },
            },
          },
          confidence: { type: 'number', description: '0-100 this is real AND a genuine gap' },
        },
      },
    },
  },
}

const MERGE_SCHEMA = {
  type: 'object', additionalProperties: false, required: ['master', 'dedup_notes', 'seam_notes'],
  properties: {
    master: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        required: ['title', 'family', 'summary', 'writable_field', 'safe_field', 'evidence', 'coverage', 'detectability', 'proposed_category', 'proposed_checks', 'source_finders'],
        properties: {
          title: { type: 'string' }, family: { type: 'string' }, summary: { type: 'string' },
          writable_field: { type: 'string' }, safe_field: { type: 'string' }, why_now: { type: 'string' },
          evidence: { type: 'array', items: { type: 'object', additionalProperties: true } },
          coverage: { type: 'string' }, overlaps_existing: { type: 'string' },
          detectability: { type: 'string' }, proposed_category: { type: 'string' },
          proposed_checks: { type: 'array', items: { type: 'object', additionalProperties: true } },
          source_finders: { type: 'array', items: { type: 'string' } },
        },
      },
    },
    dedup_notes: { type: 'string' },
    seam_notes: { type: 'string', description: 'overlaps between families, and any sibling no finder covered' },
  },
}

const VERIFY_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['title', 'real_and_accurate', 'fits_invariant', 'gap_confirmed', 'in_scope', 'detectability_final', 'severity_final', 'confidence', 'verdict', 'rationale'],
  properties: {
    title: { type: 'string' },
    real_and_accurate: { type: 'boolean', description: 'cited source real and the writable-vs-safe split described correctly' },
    evidence_check: { type: 'string' },
    fits_invariant: { type: 'boolean', description: 'genuinely the writable-data-trust class, not a generic authz bug' },
    gap_confirmed: { type: 'boolean', description: 'not already in the existing checks' },
    in_scope: { type: 'boolean', description: 'has a real static signal a repo/README scanner can match' },
    detectability_final: { type: 'string', enum: ['readme', 'config', 'grep', 'trace', 'adversarial', 'runtime-precursor'] },
    severity_final: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
    confidence: { type: 'number' },
    corrections: { type: 'string' },
    verdict: { type: 'string', enum: ['KEEP', 'DEMOTE', 'DROP'] },
    rationale: { type: 'string' },
  },
}

// ---------------------------------------------------------------- FIND
phase('Find')

const FINDERS = [
  {
    key: 'supabase-postgres',
    title: 'Supabase / Postgres — writable-data trust beyond user_metadata',
    brief:
      'Find SIBLINGS of the user_metadata bug inside Supabase/Postgres that are NOT the seed bug and NOT already covered. ' +
      'Hunt: RLS / app authz keyed on a JWT claim the client can influence (custom access-token hook that copies ' +
      'user_metadata into a top-level claim, then RLS trusts it); RLS gated on a Postgres GUC the client can set ' +
      '(current_setting(\'request.\') / set_config with a client-supplied value); trusting auth.email() or an email DOMAIN ' +
      'for role (email is user-settable / spoofable pre-verification); authz on a self-updatable profiles column used as ' +
      'role when only some columns are WITH CHECK-guarded; trusting `auth.role()` = authenticated when anonymous sign-ins ' +
      'are enabled; client-supplied `app_metadata` on signUp options being accepted. For each, give the concrete grep/SQL ' +
      'signal and the safe alternative. Already covered (do not re-propose): rls-policy-user-metadata-bypass, ' +
      'user-metadata-authz-client, supabase-anon-write-privilege-billing, supabase-security-definer-view-or-rpc, ' +
      'supabase-db-side-ssrf-and-search-path, getsession-unverified-serverside, supabase-realtime-or-anon-auth-gap.',
  },
  {
    key: 'managed-auth-providers',
    title: 'Managed auth providers — writable vs server-only metadata, same bug different vendor',
    brief:
      'The seed bug is vendor-agnostic: every managed-auth provider has a user-writable metadata bucket and a server-only ' +
      'one, and developers confuse them. FETCH each vendor doc and report the exact split + the static tell when authz reads ' +
      'the writable side. Cover: Auth0 (user_metadata writable vs app_metadata server-only; authz on user_metadata.roles); ' +
      'Clerk (publicMetadata server-set-readable, privateMetadata server-only, unsafeMetadata CLIENT-WRITABLE via ' +
      'user.update() — authz on unsafeMetadata.role is the bug); AWS Cognito (custom: attributes that are mutable / ' +
      'writable by the user unless explicitly read-only; authz on a mutable custom:role); Firebase (custom claims via ' +
      'admin.setCustomUserClaims are safe, but authz read from a user-writable Firestore /users/{uid} role field is not); ' +
      'Stytch / WorkOS / Supabase Auth / NextAuth / Lucia / Better-Auth session or trusted_metadata equivalents. ' +
      'Give per-vendor grep signals (e.g. unsafeMetadata\\.(role|isAdmin|plan)). NOT already covered as vendor-specific.',
  },
  {
    key: 'jwt-token-claims',
    title: 'JWT / ID-token / social-claim trust',
    brief:
      'Find writable-data-trust siblings in token handling that go BEYOND the covered jwt-decode-not-verify / ' +
      'jwt-alg-none-or-confusion / getsession-unverified-serverside. Hunt: trusting an OIDC/social-login claim that the ' +
      'provider does NOT guarantee (email / email_verified=false trusted as verified; trusting `hd` / domain claim; ' +
      'trusting `name`/`picture`); account-linking by unverified email (link to an existing account using an email claim ' +
      'that was never verified -> takeover); trusting a self-asserted `roles`/`groups`/`scope` claim minted by a misconfigured ' +
      'IdP or copied from user input; trusting `aud`/`iss` not validated so a token from another app/tenant is accepted; ' +
      'mobile/SPA passing a client-decoded id_token whose claims are trusted server-side. Give the grep signal (claim name ' +
      'adjacent to an authz/branch) and the verify-side fix. Cite OIDC spec / provider docs / real takeover writeups.',
  },
  {
    key: 'request-shaped-identity',
    title: 'Request-shaped identity & entitlement trust (headers / body / query / cookie)',
    brief:
      'The same invariant where the writable datum is part of the HTTP request the client fully controls. Go DEEPER than the ' +
      'covered trust-client-supplied-identity / mass-assignment-role / rate-limit-bypass-trusted-header / public-id-as-auth-' +
      'boundary. Hunt specific, current variants: trusting x-forwarded-* / x-real-ip / x-forwarded-host for authz or origin ' +
      'decisions (not just rate limit); trusting a custom identity header injected by a gateway but reachable directly ' +
      '(x-user-id / x-user-email / x-authenticated-user / x-tenant-id) because the upstream does not strip it; GraphQL ' +
      'field/auth directive trusting a client-supplied arg as the owner id; tRPC/route input carrying role/tenant used ' +
      'without re-deriving from session; trusting a signed-but-client-readable cookie field (role in a non-HMAC cookie); ' +
      'Next.js Server Actions / RSC trusting a hidden form field for identity. Give grep signals + safe pattern.',
  },
  {
    key: 'other-baas-and-realtime',
    title: 'Other BaaS, realtime & edge — client-writable trust',
    brief:
      'Extend the invariant to BaaS/realtime/edge platforms beyond Supabase. FETCH docs and find the writable-vs-safe split ' +
      'plus the static tell. Cover: Firebase Security Rules trusting a client-written field (request.resource.data.role / a ' +
      'role stored in the doc the user can write) instead of request.auth.token custom claims, and App Check absence as the ' +
      'enabler; Appwrite (team/role vs user prefs that the user can set), Nhost (Hasura x-hasura-role / x-hasura-* headers ' +
      'trusted from the client when the unauthenticated/webhook path lets the client pick the role), PocketBase / Convex / ' +
      'InstantDB rules trusting client fields; Hasura permissions trusting a session variable the client supplies; ' +
      'Cloudflare Workers / Durable Objects trusting a request-derived name or a client-set header for tenant. Mark what is ' +
      'PARTIAL vs firebase-rules-open-or-auth-only / firebase-no-appcheck / cloudflare-do-idfromname-idor / ' +
      'edge-function-verify-jwt-disabled. Give the rule/config grep signal.',
  },
  {
    key: 'ai-scaffold-auth-defaults',
    title: 'AI-codegen scaffold auth defaults that bake in writable-data trust',
    brief:
      'The seed bug is something AI coding tools EMIT. Research the SPECIFIC, named, current insecure auth defaults that ' +
      'Lovable / Bolt.new / v0 / Replit Agent / Cursor / Base44 / Claude/Copilot-generated apps ship, focused on the ' +
      'writable-trust invariant: role/isAdmin kept in localStorage or a client store and trusted; client-side route guards ' +
      '(ProtectedRoute) as the ONLY gate; mock/stub auth or hardcoded `const user = {role:"admin"}` left in; auth state in a ' +
      'cookie/JWT the client can edit; Supabase scaffolds that read user_metadata.role (the seed) or leave RLS off. Find ' +
      'systematic studies / disclosures quantifying these defaults (Socket, Trend Micro, the Lovable RLS exposure / ' +
      '"VibeScamming" reporting, academic vuln-rate studies of generated code). This is PARTIAL vs the generic ' +
      'vibe-coded-scaffold-insecure-defaults and authz-only-in-frontend — propose the SPECIFIC drop-in grep signals (e.g. ' +
      'localStorage.*(role|isAdmin) , ProtectedRoute as sole guard) and README red-flags. Cite the studies.',
  },
]

const finderResults = await parallel(FINDERS.map((f) => () =>
  agent(
    'You are a senior application-security + AI-security researcher hunting NEW detection avenues for a static security ' +
    'scanner, focused on ONE vulnerability class.\n\n' + INVARIANT + '\n\nYOUR FAMILY: ' + f.title + '\n\n' + f.brief +
    '\n\n' + SCANNER_NATURE + '\n\n' + COVERAGE_INSTRUCTION + '\n\n' + TOOLING + '\n\n' + ANTIFAB + '\n\n' +
    'Return 3-7 high-quality avenues (quality over quantity), each a genuine sibling of the seed bug. Fill the schema: name ' +
    'the writable_field and the safe_field explicitly, why it is silent, real cited evidence (prefer the vendor doc that ' +
    'documents the split), NEW-vs-PARTIAL naming the closest existing check id, the right detectability tier, and 1-4 ' +
    'concrete proposed checks with grep signals (include the file extensions) / README red-flags / fix. Skip anything ' +
    'COVERED. Your final message is the structured object only.',
    { label: 'find:' + f.key, phase: 'Find', agentType: 'general-purpose', schema: FINDER_SCHEMA }
  ).then((r) => ({ key: f.key, title: f.title, avenues: (r && r.avenues) || [] }))
))

const finders = finderResults.filter(Boolean)
const rawCount = finders.reduce((n, fr) => n + fr.avenues.length, 0)
log('Find done: ' + finders.length + '/' + FINDERS.length + ' finders returned, ' + rawCount + ' raw candidate avenues')

// ---------------------------------------------------------------- MERGE
phase('Merge')

const mergeInput = finders.map((fr) =>
  '## FAMILY: ' + fr.key + ' (' + fr.title + ')\n' +
  fr.avenues.map((a, i) =>
    '- [' + fr.key + '#' + (i + 1) + '] ' + a.title + ' | coverage=' + a.coverage + ' | detect=' + a.detectability +
    ' | cat=' + a.proposed_category +
    '\n    writable: ' + a.writable_field + '  ->  safe: ' + a.safe_field +
    '\n    summary: ' + a.summary +
    '\n    overlaps: ' + (a.overlaps_existing || 'none') +
    '\n    evidence: ' + (a.evidence || []).map((e) => e.kind + ':' + e.ref + (e.url ? ' <' + e.url + '>' : '')).join(' ; ') +
    '\n    proposed_checks: ' + (a.proposed_checks || []).map((c) => '[' + c.severity + '/' + c.detectability + '] ' + c.title).join(' | ')
  ).join('\n')
).join('\n\n')

const merged = await agent(
  'You are consolidating candidate detection avenues for ONE vulnerability class (the writable-data-trust invariant) from ' +
  '6 parallel finders into ONE clean master list for a static repo/README scanner (git-gud-security).\n\n' + INVARIANT +
  '\n\n' + SCANNER_NATURE + '\n\nRaw candidates:\n\n' + mergeInput + '\n\n' +
  '1. DEDUP: merge avenues that are the same idea (e.g. the same vendor-metadata bug found by two finders); keep the ' +
  'clearest title, union evidence + proposed checks, record contributing finders in source_finders.\n' +
  '2. NORMALIZE: keep each avenue\'s strongest 1-4 proposed checks; carry writable_field, safe_field, detectability, ' +
  'proposed_category, evidence.\n' +
  '3. PRUNE non-siblings: drop anything that is a generic authz bug NOT driven by a framework-writable datum, or that is ' +
  'plainly already covered; note why in dedup_notes.\n' +
  '4. SEAM CHECK: in seam_notes, call out overlaps between families AND any sibling of the seed bug NONE of the finders ' +
  'covered that a 2026 scanner still needs.\n\nAim for 15-25 deduplicated avenues. Return the structured object only.',
  { label: 'merge', phase: 'Merge', agentType: 'general-purpose', schema: MERGE_SCHEMA }
)

const master = (merged && merged.master) || []
log('Merge done: ' + master.length + ' deduplicated avenues; verifying each adversarially')

// ---------------------------------------------------------------- VERIFY
phase('Verify')

const verdicts = await parallel(master.map((a, idx) => () =>
  agent(
    'You are an adversarial verifier. Default to DROP unless the avenue passes ALL tests.\n\n' + INVARIANT + '\n\n' +
    'AVENUE #' + (idx + 1) + ': ' + a.title + '\n' +
    'writable_field: ' + a.writable_field + '  ->  safe_field: ' + a.safe_field + '\n' +
    'summary: ' + a.summary + '\n' +
    'claimed coverage: ' + a.coverage + ' | overlaps: ' + (a.overlaps_existing || 'none') + ' | detect: ' + a.detectability + '\n' +
    'evidence: ' + (a.evidence || []).map((e) => (e.kind || '?') + ':' + (e.ref || '?') + (e.url ? ' <' + e.url + '>' : '')).join(' ; ') + '\n' +
    'proposed checks: ' + (a.proposed_checks || []).map((c) => '[' + c.severity + '/' + c.detectability + '] ' + c.title).join(' | ') + '\n\n' +
    'FIVE TESTS:\n' +
    '1. REAL & ACCURATE: use WebSearch/WebFetch to confirm the cited vendor-doc / CVE / incident exists and that the ' +
    'writable-vs-safe split is described CORRECTLY (e.g. is that field actually client-writable by default?). A wrong/' +
    'unfindable claim fails; note the correction.\n' +
    '2. FITS THE INVARIANT: is the trusted datum writable/forgeable BY FRAMEWORK DEFAULT, and is this more than a generic ' +
    'missing-authz bug? If it is just "no authz check", set fits_invariant false.\n' +
    '3. GENUINE GAP: re-read the existing coverage; if a listed check already handles it, set gap_confirmed false.\n' +
    '4. IN SCOPE: is there a real static signal (token/config/README) a scanner can match? If only observable at runtime ' +
    'with no static precursor, set in_scope false.\n' +
    '5. SEVERITY & TIER SANITY: pick the correct final severity and detectability tier; demote inflated ones.\n\n' +
    SCANNER_NATURE + '\n\n' + COVERAGE_INSTRUCTION + '\n\n' + TOOLING + '\n\n' +
    'Verdict: KEEP if all pass; DEMOTE if real+sibling+gap+in-scope but overstated (say how); DROP if it fails REAL, ' +
    'INVARIANT, GAP, or IN-SCOPE. Return the structured object only.',
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
    'family: ' + (a.family || '') + ' | proposed_category: ' + a.proposed_category + '\n' +
    'writable_field: ' + a.writable_field + '  ->  safe_field: ' + a.safe_field + '\n' +
    'final severity: ' + v.severity_final + ' | final detectability: ' + v.detectability_final + ' | confidence: ' + v.confidence + '\n' +
    'summary: ' + a.summary + '\n' +
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
  'You are writing the final research deliverable for git-gud-security: a roadmap of NEW checks for the writable-data-trust ' +
  'vulnerability class (the Supabase user_metadata bug and its siblings). Audience: the tool author, a solo builder who ' +
  'hates fluff, AI cadence, em-dashes, and fabrication; wants a prioritized recommendation, not a menu.\n\n' + INVARIANT +
  '\n\n' + SCANNER_NATURE + '\n\nVERIFIED SURVIVING AVENUES (already adversarially checked, corrections applied):\n\n' +
  survivorBlock + '\n\nDROPPED (appendix, one line each):\n' + droppedBlock + '\n\nMERGE SEAM NOTES: ' +
  ((merged && merged.seam_notes) || 'none') + '\n\n' +
  'Write a tight markdown report:\n' +
  '1. **Bottom line** — 3-5 sentences: the highest-value siblings to add and the one-sentence theme of where the library ' +
  'is blind to this class.\n' +
  '2. **P0 — add now** — best impact x fit x ease-of-detection. For each: one-line description, writable->safe field pair, ' +
  'where it slots (extend category X), detectability tier, severity, and the concrete check(s) ready to drop into ' +
  'patterns.json / checks.data.json (id + title + grep signals with file extensions + readme red-flags + fix). Model them ' +
  'on the existing user-metadata-authz-client entry.\n' +
  '3. **P1 — strong adds** — same format, lower priority.\n' +
  '4. **P2 — worth having** — terse list, title + one line.\n' +
  '5. **A single generalized check?** — assess whether one parameterized "authz keyed on a known client-writable field" ' +
  'check (a table of {writable_field, safe_field, vendor}) beats N per-vendor checks, and recommend.\n' +
  '6. **Out of scope / runtime-only** — real but not statically catchable; say why so the author does not chase them.\n' +
  '7. **Appendix: dropped candidates**.\n\n' +
  'Rules: cite the real source (vendor doc / CVE / incident) inline where it backs a recommendation. No em-dashes, no ' +
  '"not X but Y", no three-beat filler, no emoji, no flattery. Terse and concrete. Every proposed check names a static ' +
  'signal with the file extensions it greps. Return ONLY the markdown report.',
  { label: 'synthesize', phase: 'Synthesize', agentType: 'general-purpose' }
)

return {
  counts: { finders: finders.length, rawAvenues: rawCount, merged: master.length, kept: kept.length, dropped: dropped.length },
  report: report,
}
