# README red flags — fast lookup for `readme` mode

<!-- generated from scripts/checks.data.json by scripts/build_checks.py — do not hand-edit -->

Phrases and claims in a README / landing page / docs that betray a specific hole, grouped by hole. Seeing one makes the hole *likely* (mark it inferred, not confirmed, unless the README literally shows the vulnerable thing). Full detail is in `checks.md` under the `id`.

Scan the target's prose against these. Up to 3 most diagnostic phrasings per hole; the model generalizes from the pattern, so an inexact match still counts.

## Secrets & Credentials

- **Service/admin key shipped to the client (RLS bypass)** `service-role-key-in-client` · crit
  "fully serverless, no backend needed" · "just add your service role key to .env" · "talks to Supabase directly from the frontend"
- **Private secret wrapped in a public env prefix** `secret-behind-public-env-prefix` · crit
  "add your OpenAI/Stripe/Anthropic key to NEXT_PUBLIC_..." · "set VITE_API_KEY in your env" · "no backend, the app calls the API directly from React"
- **Hardcoded API key/token as a string literal in source** `hardcoded-api-key-literal` · crit
  "works out of the box, no setup" · "pre-configured with my account" · "API key included for convenience"
- **Real .env / credential file committed to the repo** `committed-dotenv-or-cred-file` · crit
  "clone and run, the .env is already set up" · "copy my .env values" · "everything you need is in the repo"
- **Secret inlined into the built JS bundle or leaked via source maps** `secret-in-client-bundle-or-sourcemaps` · crit
  "100% client-side, host on any static CDN" · "no server, deploy to GitHub Pages" · "source maps enabled for easier debugging in prod"
- **Private key / certificate material committed** `private-key-file-committed` · crit
  "ssh key included for deploy" · "use the bundled cert" · "GCP credentials included"
- **Credentials hardcoded in MCP/plugin/skill manifest or hook** `secret-in-mcp-or-plugin-manifest` · crit
  "drop this config into Claude Desktop, it's ready" · "my MCP config with keys included" · "install this skill, the API key is already wired"
- **JWT/session/webhook signing secret hardcoded, weak, or committed** `jwt-or-signing-secret-weak-or-committed` · crit
  "default JWT secret works for dev" · "JWT_SECRET=changeme in the sample env" · "webhook secret is in the config"
- **Modern AI/infra API key format committed (newer provider prefixes)** `secret-modern-key-prefix-sweep` · crit
  "add your Supabase secret key" · "paste your HuggingFace / Groq / Replicate token" · "API key included"
- **Secret removed from HEAD but still in git history** `secret-in-git-history` · high
  "we rotated the leaked key, it's fine now" · "the key was removed in a later commit"
- **Live credential pasted into README, docs, or example config** `secret-in-readme-or-docs` · high
  "here's my key to get you started" · "use this token to test" · "example request (works as-is)"
- **Database/connection URL with embedded password committed** `db-connection-string-with-password` · high
  "point it at my database, the URL is in config" · "shared dev DB, connection string included"
- **API key embedded in a shipped mobile app** `secret-in-mobile-app-binary` · high
  "add your key to app.json" · "no backend, the app talks to the API directly"
- **Secrets written to logs, console, or error/telemetry sinks** `secrets-logged-to-console-or-telemetry` · high
  "verbose/debug logging on by default" · "logs everything for easy debugging" · "rich error context, captures request bodies"
- **Secret echoed in CI logs or baked into Docker build args/layers** `secret-in-ci-logs-or-image-layers` · high
  "CI is set up, secrets are in the workflow file" · "build with --build-arg API_KEY=..." · "the image comes preconfigured"
- **Encryption key/IV/salt hardcoded as a constant** `encryption-key-or-iv-hardcoded` · high
  "data is encrypted (with a built-in key)" · "no key management needed"
- **Secrets in newer deploy/config files (.dev.vars, wrangler vars, *.local, devcontainer)** `secrets-in-newer-deploy-config-files` · high
  "copy .dev.vars" · "put your secrets in wrangler.toml vars"
- **Credential visible in a committed screenshot or asset** `secret-in-screenshot-or-asset` · med
  "see screenshot for my setup" · "here's my config (image)"
- **Secrets/tokens passed in URLs (logged by servers, proxies, referrers)** `secret-in-url-query-params` · med
  "authenticate by adding ?api_key= to the URL" · "pass your token in the link" · "shareable URL includes the access token"
- **Confusing safe-to-expose keys with secret keys** `safe-public-key-misflagged` · low
  "the anon key is public, that's by design" · "publishable key in the frontend (fine) vs secret key in the frontend (not)"

## Auth, Access Control & Account Lifecycle

- **API endpoint / route handler with no authentication check** `no-authz-on-endpoint` · crit
  "no login required" · "open API, no auth needed" · "internal tool, trusted network"
- **IDOR: object accessed by client-supplied id with no ownership check** `idor-object-level-authz` · crit
  "access any record by id" · "share links by changing the id in the URL" · "simple REST API, fetch any record by id"
- **Trusting a client-supplied user_id / role / tenant instead of the session** `trust-client-supplied-identity` · crit
  "pass the user id in the request body" · "send X-User-Id header to identify the caller" · "client tells the server who it is"
- **Missing tenant scoping (cross-tenant data access)** `broken-multi-tenant-isolation` · crit
  "multi-tenant SaaS" · "single shared database" · "workspaces / organizations"
- **Admin route gated by a hardcoded/guessable secret or backdoor** `hardcoded-or-guessable-admin-key` · crit
  "admin password is admin" · "set ?admin=true to access the dashboard" · "default admin key in config"
- **JWT decoded but signature never verified** `jwt-decode-not-verify` · crit
  "we decode the JWT to get the user" · "stateless auth, just read the token"
- **JWT accepts alg=none or no algorithm allowlist** `jwt-alg-none-or-confusion` · crit
  "supports any JWT algorithm" · "algorithm auto-detected from the token" · "flexible token signing"
- **Passwords stored plaintext or with a fast/unsalted hash** `plaintext-or-weak-password-hash` · crit
  "passwords stored for easy recovery" · "we can email you your password" · "simple sha256 hashing"
- **Auth enforced only in Next.js middleware (CVE-2025-29927 / header spoof)** `nextjs-middleware-auth-bypass` · crit
  "auth handled in middleware" · "protected routes via middleware matcher" · "single auth gate at the edge"
- **Mass assignment / over-posting lets client set role, isAdmin, plan** `mass-assignment-role` · high
  "send the whole object, we persist it" · "flexible schema, just post JSON" · "no DTO needed"
- **Authorization enforced only in the frontend (hidden UI, open API)** `authz-only-in-frontend` · high
  "role-based UI" · "admins see extra buttons" · "frontend hides what you can't use"
- **Authenticated-but-not-authorized: any logged-in user can do admin actions** `missing-role-check-priv-esc` · high
  "all logged-in users can manage content" · "role system planned" · "everyone's an admin for now"
- **Default-allow authorization (fails open)** `default-allow-authz` · high
  "open by default for easy setup" · "permissive mode" · "allow-all fallback"
- **Default/example credentials left active** `default-example-credentials` · high
  "login with admin / admin" · "default password is changeme" · "demo account: admin@example.com / password"
- **JWT/session token with no expiry or no expiry validation** `jwt-no-expiry-validation` · high
  "tokens never expire" · "log in once, stay in forever" · "no session timeout"
- **Password reset token weak, non-expiring, or not bound to the user** `password-reset-token-weak` · high
  "simple password reset" · "reset link never expires" · "magic reset by email only"
- **No rate limiting / lockout on auth, OTP, and reset endpoints** `missing-rate-limit-auth` · high
  "no rate limiting" · "unlimited login attempts" · "lightweight, no throttling"
- **Auth/session cookie missing HttpOnly/Secure/SameSite or scoped too broadly** `insecure-cookie-flags` · high
  "token stored in localStorage" · "JWT in local storage for convenience" · "single sign-on across all *.example.com"
- **OAuth/SSO flow missing state, open redirect_uri, or unverified id_token** `oauth-state-redirect-token-validation` · high
  "login with Google/GitHub in one step" · "configurable redirect URL" · "we trust the provider's email"
- **No CSRF protection on cookie-authenticated state-changing requests** `missing-csrf-protection` · high
  "no CSRF tokens needed" · "simple cookie auth" · "we removed CSRF middleware because it was annoying"
- **No 2FA/MFA on critical accounts and publish registries** `missing-2fa-critical-accounts` · high
  "publish with npm publish using NPM_TOKEN" · "single maintainer account" · "deploy keys checked into the repo"
- **Password-reset token placed in the URL, leaked via Referer / logs / analytics** `reset-token-in-url-referer-leak` · high
  "magic reset by email only" · "click the link, that's it, no code to type" · "we use Google Analytics / PostHog / Sentry on every page"
- **Reset/verification link built from the request Host header (host-header poisoning)** `host-header-poisoned-reset-link` · high
  "works on any domain automatically" · "no need to set a base URL, it figures it out" · "multi-tenant, each customer on their own host"
- **Reset token reusable, not single-use, or other tokens not revoked on password change** `reset-token-not-invalidated-on-use-or-reuse` · high
  "reset link works for 24h, click it whenever" · "stateless reset tokens, nothing stored server-side" · "no session table, JWT only"
- **Email change without verifying the new address or re-authenticating the user** `email-change-no-verify-or-reauth` · high
  "edit your email anytime in settings" · "instant profile updates" · "change your email, no confirmation needed"
- **No step-up re-authentication for password/email/MFA changes or account deletion** `no-reauth-for-sensitive-actions` · high
  "change your password right in settings, one click" · "manage 2FA from your dashboard" · "delete your account instantly"
- **OAuth callback honors an attacker-controlled redirect / loosely-matched redirect_uri allowlist** `oauth-callback-open-redirect-allowlist` · high
  "configurable redirect URL" · "we send you back wherever you came from" · "login with Google/GitHub in one step"
- **Magic-link / email-OTP replayable, multi-use, or not bound to the requesting context** `magic-link-otp-replay-no-binding` · high
  "passwordless, just click the link" · "magic links never expire / valid for a week" · "enter the 6-digit code we email you"
- **Invite / email-verification token is guessable, sequential, or IDOR-able** `idor-invite-or-verify-token-guessable` · high
  "share this invite link with your team" · "verify by clicking the link in your email" · "invite links by id"
- **Server Action / framework action mutates with no inline authorization** `server-action-no-inline-authz` · high
  "auth is handled in middleware" · "protected routes"
- **Client-visible app/project/tenant id used as the auth boundary** `public-id-as-auth-boundary` · high
  "just pass your app id" · "no login needed, scoped by project id"
- **Unverified client session used for server-side auth decisions** `getsession-unverified-serverside` · high
  "uses getSession for auth checks" · "checks session on the server"
- **User enumeration via login / reset / signup responses** `user-enumeration` · med
  "tells you if the email exists" · "helpful login error messages" · "checks if username is taken"
- **Session id not rotated on login / privilege change** `session-fixation-no-rotation` · med
  "session id in the URL" · "persistent session across login" · "stateless sessions, no rotation"
- **OAuth implicit flow returns access/id token in the URL fragment** `implicit-flow-token-in-fragment` · med
  "pure SPA, no backend, tokens handled in the browser" · "implicit flow for simplicity" · "we read the token straight from the URL"
- **Signup with no email verification, enabling impersonation and unverified-trust** `signup-no-email-verification-impersonation` · med
  "sign up and start instantly, no email confirmation" · "we trust the provider's email" · "no verification step to reduce friction"
- **"Remember me" / refresh tokens never expire, not revocable, and not rotated** `remember-me-and-refresh-token-never-expire` · med
  "stay logged in forever" · "remember me keeps you signed in indefinitely" · "tokens stored in AsyncStorage for convenience"

## Database, RLS & Cloud Config

- **Table in PostgREST-exposed schema with RLS disabled** `supabase-rls-disabled-public-table` · crit
  "disabled RLS for development" · "RLS off for now, we'll add policies later" · "just point the frontend at Supabase, no backend needed"
- **RLS policy with USING (true) / WITH CHECK (true) on sensitive table** `supabase-rls-policy-using-true` · crit
  "public read access for everyone" · "anyone can read/write" · "open access policy"
- **anon/authenticated INSERT/UPDATE on privilege or billing tables** `supabase-anon-write-privilege-billing` · crit
  "users manage their own subscription rows" · "client writes to the entitlements table"
- **Firebase/Firestore/RTDB/Storage rules open or auth-presence-only** `firebase-rules-open-or-auth-only` · crit
  "Firebase in test mode" · "open security rules for now" · "no auth needed, fully open database"
- **Firebase Admin SDK / service account used client-side** `firebase-admin-sdk-in-client` · crit
  "uses Firebase Admin for full access" · "no security rules needed, admin handles it" · "drop in your service account json"
- **MongoDB/Redis/Elasticsearch/Postgres with no auth and exposed port** `datastore-no-auth-public` · crit
  "spin up Mongo with docker, no config needed" · "Redis for sessions, no password needed" · "Elasticsearch with security off for simplicity"
- **RLS policy references user-writable metadata (trivially bypassable)** `rls-policy-user-metadata-bypass` · crit
  "uses metadata for role checks" · "roles stored in user profile"
- **Authorization decision gated on user-writable user_metadata (app code)** `user-metadata-authz-client` · crit
  "role stored in user metadata" · "set the user's role on signup metadata"
- **SECURITY DEFINER view/RPC bypasses RLS or lacks internal authz** `supabase-security-definer-view-or-rpc` · high
  "we expose a flattened view for the frontend" · "call our database functions directly from the client" · "RPC helpers for everything"
- **BYPASSRLS role fronting the API or over-broad PostgREST exposed schema** `postgres-bypassrls-or-exposed-schema` · high
  "uses an admin role for simplicity" · "service role for all queries" · "all tables auto-exposed as REST endpoints"
- **Public storage bucket with PII or storage.objects with no/loose policies** `supabase-storage-bucket-or-objects-open` · high
  "public bucket for uploads" · "files served from a public URL" · "no auth needed to view uploads"
- **Public/listable S3 / R2 / GCS bucket or wildcard bucket policy** `public-object-storage-bucket` · high
  "public S3 bucket for assets/uploads" · "we set the bucket to public-read" · "files served straight from the bucket URL"
- **Edge/serverless function with verify_jwt disabled and no internal auth** `edge-function-verify-jwt-disabled` · high
  "public edge function endpoint" · "no auth on our API routes for simplicity" · "pass the user id in the request body"
- **Admin/debug/metrics interface bound to 0.0.0.0 or exposed unauthenticated** `exposed-admin-debug-default-port` · high
  "open by default for easy setup" · "swagger docs live at /docs" · "actuator endpoints for monitoring"
- **Sensitive data stored unencrypted at rest** `no-encryption-at-rest-sensitive` · high
  "stores your API keys locally for convenience" · "saves tokens in localStorage" · "data kept in a simple JSON/SQLite file"
- **DB backups / data exports stored world-readable or in public buckets** `backup-export-world-readable` · high
  "nightly backup to a public bucket" · "download the latest dump here" · "exports saved under /public"
- **Secrets in committed Terraform state / .tfvars / plan output** `terraform-state-secrets-committed` · high
  "just run terraform apply, state is in the repo" · "config lives in terraform.tfvars (committed)" · "no remote backend needed"
- **Secrets committed in wrangler.toml [vars] section** `wrangler-toml-secrets-in-vars` · high
  "add your API key to wrangler.toml" · "set your secrets in [vars]"
- **RLS enabled but wide GRANTs remain; relies on 'no policy = deny'** `supabase-rls-no-policy-stale-grants` · med
  "RLS enabled (secure by default)" · "we locked it down with RLS"
- **RLS protects rows but not columns; PII/secret columns selectable** `supabase-column-level-pii-leak` · med
  "single users table for everything" · "select all fields from the client"
- **Signed URL with very long expiry or leaked in logs** `signed-url-unbounded-expiry` · med
  "permanent share links" · "we generate a signed URL that never expires"
- **Realtime publication streams an RLS-off table, or anon sign-ins satisfy 'authenticated'** `supabase-realtime-or-anon-auth-gap` · med
  "live updates streamed to every client" · "guest mode / anonymous login enabled" · "no email confirmation required"
- **No Firebase App Check / open client SDK enabling rule brute-force & abuse** `firebase-no-appcheck` · med
  "client-only Firebase app" · "no server, the app writes straight to Firestore"
- **Container runs as root, privileged, or mounts the docker socket** `docker-runs-as-root-or-privileged` · med
  "docker run and you're done" · "mounts the docker socket" · "runs privileged for convenience"

## Injection & Unsafe Execution

- **SQL query built by string concatenation / f-string / template literal** `sql-string-built-query` · crit
  "raw SQL for flexibility" · "build dynamic queries from user filters" · "no ORM, we write SQL directly"
- **ORM raw/unsafe escape hatch fed user input** `orm-raw-unsafe-escape-hatch` · crit
  "drop down to raw SQL when needed" · "advanced queries via raw()" · "escape hatch for complex filters"
- **Command injection via user input concatenated into a shell command** `command-injection-shell-string` · crit
  "wraps ffmpeg / imagemagick / git / youtube-dl" · "runs the command you give it" · "shell out to system tools"
- **Dynamic code execution of user/model-controlled input (eval/exec/new Function/vm)** `code-injection-dynamic-eval` · crit
  "evaluate expressions / formulas from the user" · "scriptable rules engine" · "run user-provided JavaScript/Python snippets"
- **Server-side template injection (user input compiled as a template)** `ssti-user-template-render` · crit
  "customizable email/notification templates" · "users can edit the template" · "dynamic templating with their own variables"
- **NoSQL operator injection (raw request object used as Mongo filter)** `nosql-operator-injection` · high
  "flexible query API, pass filters straight from the client" · "MongoDB, schemaless and fast to build" · "send any JSON filter to the search endpoint"
- **Argument injection into a safe exec call (option smuggling)** `argument-injection-execfile` · high
  "we avoid shell injection by using execFile" · "args passed safely as an array" · "thin safe wrapper around the CLI"
- **Command allowlist defeated by chaining/metacharacters** `command-allowlist-bypassable` · high
  "safe command runner" · "only allowed commands run" · "sandboxed shell (allowlist)"
- **Expression-language injection (SpEL, OGNL, MVEL, JEXL, Groovy)** `expression-language-injection` · high
  "rules engine with expressions" · "user-defined formulas/conditions" · "scriptable workflow steps"
- **Dynamic require/import/module load from user- or config-controlled path** `dynamic-require-import-user-path` · high
  "plugin system loads modules by name" · "drop in your own extension" · "configurable handler/driver by string"
- **LDAP or XPath injection via filter/query built by concatenation** `ldap-xpath-injection` · high
  "LDAP / Active Directory login" · "enterprise directory search" · "queries an XML datastore"
- **Format string injection (user input used as the format string)** `format-string-injection` · med
  "custom message format strings" · "user-defined templates with placeholders" · "configurable label formatting"
- **GraphQL operation built from raw strings / resolver forwards args unparameterized** `graphql-injection-unparameterized` · med
  "flexible GraphQL API" · "query anything you need" · "auto-generated CRUD resolvers"

## SSRF, Path Traversal & Deserialization

- **SSRF reaching cloud metadata endpoint (credential theft)** `ssrf-cloud-metadata-endpoint` · crit
  "deployed on AWS/GCP/Azure/Fly" · "fetches user URLs server-side" · "serverless function that proxies requests"
- **Unsafe deserialization of untrusted data (pickle, node-serialize, Java/PHP/Ruby gadgets, fastjson, jsonpickle)** `unsafe-deserialization` · crit
  "stores sessions/objects serialized" · "accepts serialized payloads from clients" · "cross-language object exchange"
- **SSRF: user-controlled URL passed to server-side fetch/request** `ssrf-user-controlled-fetch` · high
  "fetch any URL / link preview" · "import from a URL you provide" · "screenshot or scrape a given website"
- **SSRF allowlist bypassable via redirects or DNS rebinding (TOCTOU)** `ssrf-redirect-or-dns-rebind-bypass` · high
  "fetches and follows links" · "resolves shortened URLs" · "follows redirects automatically"
- **Path traversal: user-controlled path joined to a base directory** `path-traversal-read-write` · high
  "serve files by name" · "download endpoint takes a path" · "read any file in the workspace"
- **Arbitrary file write / overwrite from user-supplied destination** `arbitrary-file-write-overwrite` · high
  "upload files, we keep the original name" · "save to a path you choose" · "plugin can write to your project"
- **Zip Slip: archive extraction writes entries outside the target dir** `zip-slip-archive-extraction` · high
  "import a project as a zip" · "upload and unpack archives" · "extract themes/plugins from a bundle"
- **XXE: XML parsed with external entities / DTDs enabled** `xxe-xml-external-entity` · high
  "accepts XML uploads / SVG / SOAP / SAML" · "parses RSS / sitemap / config XML you provide" · "imports .docx/.xlsx/.svg"
- **Prototype pollution via recursive merge / bracket assignment with user keys** `prototype-pollution-recursive-merge` · high
  "deep-merges your config" · "flexible options object" · "set nested values by dotted path"
- **ReDoS: user-supplied regex or catastrophic-backtracking pattern on user input** `redos-catastrophic-regex` · med
  "custom search patterns" · "user-defined validation rules" · "regex-powered filters you configure"

## Web Frontend, Transport & Headers

- **CORS reflects request Origin with credentials enabled** `cors-reflect-origin-credentials` · crit
  "CORS enabled for all origins" · "works from any domain / any frontend can call our API" · "cross-origin requests just work"
- **Directory listing enabled or .git/.env exposed in web root** `directory-listing-or-exposed-dotfiles` · crit
  "just deploy the whole folder" · "copy your .env into the project root and deploy" · "rsync the repo to the server"
- **DOM XSS: untrusted URL/postMessage data flows to a dangerous sink** `dom-xss-sinks` · high
  "deep links populate the page" · "renders content from the URL" · "supports rich HTML from query params"
- **window message listener without origin verification** `postmessage-no-origin-check` · high
  "embed/iframe integration" · "cross-window messaging" · "talks to the parent page"
- **Access-Control-Allow-Origin: * on authenticated/sensitive endpoints** `cors-wildcard-on-sensitive` · high
  "public API, no auth needed" · "wildcard CORS" · "accessible from anywhere"
- **Missing or unsafe Content-Security-Policy** `missing-or-weak-csp` · high
  "no CSP needed" · "we disabled CSP because it broke inline scripts" · "uses inline event handlers for simplicity"
- **No HSTS / no forced HTTPS / mixed content** `missing-hsts-and-https` · high
  "supports both http and https" · "http fallback" · "point your frontend at http://..."
- **Debug/dev mode enabled or verbose stack traces leaked in production** `debug-dev-mode-in-prod` · high
  "set DEBUG=true" · "run with --debug in production" · "detailed errors shown to help you debug"
- **Dynamic CORS origin without Vary: Origin (cache poisoning)** `cors-missing-vary-origin` · med
  "aggressively cached at the edge" · "cached on Cloudflare/CDN" · "allowlisted origins"
- **Open redirect via unvalidated redirect/next/returnUrl param** `open-redirect` · med
  "redirects back to where you came from" · "post-login returnTo / next URL" · "deep-link / continue parameter"
- **CRLF / HTTP response header injection from user input** `crlf-header-injection` · med
  "custom response headers you control" · "sets download filename from input" · "reflects a header value back"
- **No clickjacking protection (X-Frame-Options / frame-ancestors)** `missing-clickjacking-protection` · med
  "embeddable anywhere" · "drop our widget in any iframe" · "no frame restrictions"
- **GraphQL introspection enabled in prod + no depth/cost limits** `graphql-introspection-batching` · med
  "explore the full GraphQL schema" · "introspection on for tooling" · "playground available in prod"
- **Authenticated/private responses cached by service worker or CDN** `service-worker-or-cdn-cache-private-data` · med
  "fully offline, caches everything" · "PWA caches API responses for speed" · "everything is cached at the edge for speed"
- **No bot protection (CAPTCHA/Turnstile) on signup & public forms** `no-bot-protection-public-forms` · med
  "no captcha needed" · "frictionless signup" · "open signup, no verification"
- **No rate limiting / cost cap on expensive or third-party-billed endpoints** `no-rate-limit-expensive-endpoints` · med
  "free unlimited AI calls" · "no quotas" · "generate as much as you want"
- **Missing nosniff / Referrer-Policy / Permissions-Policy** `missing-misc-security-headers` · low
  "serves arbitrary uploaded files" · "magic link / token in the URL" · "embeds third-party widgets"

## File Handling & Uploads

- **User uploads served from the app's own origin (uploaded HTML/SVG executes as stored XSS)** `upload-served-from-app-origin-stored-xss` · crit
  "uploads served straight from our domain" · "files served from the same domain for simplicity" · "user avatars / attachments hosted at app.com/uploads"
- **SVG accepted as an image and served inline with embedded JavaScript** `svg-upload-with-embedded-script` · high
  "supports SVG avatars / logos" · "upload any image including SVG" · "vector icons uploaded by users"
- **File type validated only by client-supplied Content-Type or extension (no magic-byte check)** `upload-content-type-trusted-from-client` · high
  "we check the file type before accepting" · "only images allowed (validated by type)" · "accepts images, validated client-side"
- **Uploaded images stored as-is without re-encoding (polyglots, ImageMagick/ImageTragick payloads)** `image-not-reencoded-polyglot` · high
  "we keep the original file untouched" · "powered by ImageMagick for conversions" · "original quality preserved, no re-compression"
- **Decompression / zip / image bomb processed without expansion limits** `decompression-bomb-zip-image` · high
  "import a project as a zip" · "upload and we unpack it" · "bulk import via archive"
- **Uploaded files at predictable/guessable URLs with no per-file authorization (file IDOR)** `predictable-upload-url-file-idor` · high
  "files served from a public URL" · "share by sending the link" · "no auth needed to view uploads"
- **Upload destination built from the client-supplied filename (path traversal / overwrite)** `path-traversal-in-upload-filename` · high
  "we keep the original filename" · "files saved under their uploaded name" · "preserves your folder structure on upload"
- **Direct browser-to-bucket uploads (presigned/direct) with no server-side validation** `direct-to-bucket-upload-no-validation` · high
  "uploads go straight to the bucket" · "direct-to-S3 uploads, no server in the path" · "client uploads directly to storage for speed"
- **No size cap on uploads (memory/disk exhaustion, denial of service)** `no-upload-size-cap-resource-exhaustion` · med
  "no size limits, upload anything" · "no rate limits, hammer it all you want" · "upload files of any size"
- **Double-extension and null-byte filename tricks defeat extension filtering** `double-extension-null-byte-filename-bypass` · med
  "we block .php/.exe uploads" · "blacklist of dangerous extensions" · "only safe extensions allowed (deny-list)"
- **EXIF / metadata (GPS coordinates, device, timestamps) leaked in served uploads** `exif-geolocation-metadata-leak` · med
  "original photo quality preserved" · "we keep the original file" · "metadata preserved for photographers"
- **User uploads stored and redistributed with no malware scanning** `no-malware-scan-on-uploads` · med
  "upload and share any file" · "send files to other users" · "no scanning, files go through as-is"
- **Uploads served with sniffable Content-Type and inline Content-Disposition** `unsafe-content-disposition-content-type-on-download` · med
  "serves arbitrary uploaded files" · "files open in the browser" · "preview any uploaded file inline"

## Caching, CDN & DNS

- **Authenticated/personalized response sent with public/shared cacheability** `cache-control-public-on-private-response` · crit
  "we cache everything at the edge for speed" · "put Cloudflare in front and turn on Cache Everything" · "responses are cached on the CDN so the app feels instant"
- **Shared CDN cache key omits the auth/cookie dimension (no auth-aware Vary)** `cdn-cache-key-ignores-auth` · crit
  "we cache by URL for maximum hit rate" · "Cloudflare ignores cookies so caching works" · "stripped cookies at the edge to improve cache hit ratio"
- **Web cache deception: appending a static-looking suffix gets a private page cached** `cache-deception-static-extension` · high
  "static assets are cached by extension at the edge" · "anything ending in .js/.css is cached automatically" · "we cache /static and /assets aggressively"
- **Web cache poisoning via an unkeyed request header reflected into the cached response** `cache-poisoning-unkeyed-header` · high
  "we read X-Forwarded-Host to build absolute URLs behind the proxy" · "trusts the proxy headers for the host" · "self-referencing URLs computed from the request host"
- **stale-while-revalidate / stale-if-error serving private data from a shared cache** `stale-while-revalidate-leaks-private` · high
  "uses stale-while-revalidate to keep things fast" · "ISR caches the page and revalidates in the background" · "we cache the API response and refresh it lazily"
- **Subdomain takeover via dangling CNAME to an unclaimed provider target** `subdomain-takeover-dangling-cname` · high
  "we moved the blog/docs off X but kept the subdomain" · "deprecated the old Heroku/Netlify app" · "points status.ourapp.com at a third-party"
- **Dangling A/AAAA record to a released cloud IP (reclaimable address)** `dangling-dns-a-record-reclaimable-ip` · high
  "we tore down the old VPS but the DNS still points at it" · "uses an elastic IP we sometimes release" · "spin instances up and down behind this subdomain"
- **Origin server reachable directly, bypassing the CDN/WAF** `exposed-origin-defeats-cdn-waf` · high
  "point your DNS straight at the server IP" · "origin is at 1.2.3.4 (in the config)" · "we put Cloudflare in front for DDoS protection"
- **Edge/CDN reflects request Origin into Access-Control-Allow-Origin (overly broad CORS)** `cdn-cors-reflects-origin-at-edge` · high
  "CORS is handled at the edge / in Cloudflare" · "we add CORS headers in vercel.json for all routes" · "allow any origin so the mobile/web client can call it"
- **Missing or permissive SPF/DKIM/DMARC enables email spoofing of the domain** `missing-spf-dkim-dmarc` · med
  "sends emails from noreply@ourdomain" · "transactional email via SendGrid/Resend/SES/Postmark" · "we send password resets and receipts from the app"
- **Open mail relay or unvalidated From/Reply-To enabling spoofed outbound mail** `open-email-relay-or-spoofable-from` · med
  "users can send emails from their own address through us" · "invite feature emails anyone you enter" · "our SMTP relay is open for the app"

## Cryptography, Tokens & Randomness

- **Passwords stored reversibly (encrypted/encoded) so they can be recovered** `reversible-encrypted-or-recoverable-passwords` · crit
  "we can email you your password" · "passwords stored encrypted so we can recover them" · "password recovery sends your current password"
- **JWT/cookie/session signed with a guessable or default secret** `guessable-jwt-or-cookie-signing-secret` · crit
  "default JWT secret is fine for now" · "JWT_SECRET=secret" · "session secret set in code"
- **Math.random() / weak RNG used to mint security-sensitive tokens** `insecure-rng-for-security-tokens` · high
  "simple random token generator" · "generates a quick random string for the session" · "lightweight invite codes, no dependencies"
- **Hardcoded / static IV or salt reused across all encryptions** `static-or-hardcoded-iv-or-salt` · high
  "fixed IV for deterministic output" · "we use a constant salt so encryption is reproducible" · "same key and IV everywhere for simplicity"
- **ECB mode or unauthenticated encryption (no integrity / pattern leakage)** `ecb-mode-or-unauthenticated-cipher` · high
  "AES-ECB encryption" · "lightweight XOR cipher" · "we encrypt with DES/3DES"
- **Home-grown crypto / hashing scheme instead of a vetted primitive** `roll-your-own-crypto-or-homemade-hashing` · high
  "our own lightweight encryption" · "custom hashing for speed" · "simple obfuscation of the token"
- **Sequential / auto-increment IDs exposed in URLs and APIs enable enumeration** `enumerable-sequential-resource-ids` · med
  "clean REST URLs with numeric ids" · "share a link with the order number" · "public profile at /u/{id}"
- **Secrets/tokens/HMACs compared with ==, ===, or strcmp (timing leak)** `non-constant-time-secret-comparison` · med
  "we check the signature matches before processing" · "simple token check on the admin route" · "compare the provided key to ours"
- **Token / code too short or drawn from a tiny alphabet (brute-forceable)** `short-or-low-entropy-token` · med
  "short, friendly 6-character codes" · "4-digit verification code" · "tiny share links"
- **UUIDv1 / timestamp-based id used where the value must be unguessable** `uuidv1-or-timestamp-id-where-unguessable-needed` · med
  "UUIDs so they're unguessable" · "time-sortable unique tokens" · "ObjectId as the share token"
- **API keys / coupon / license codes generated from predictable inputs** `predictable-api-key-or-coupon-generation` · med
  "API key is a hash of your account" · "deterministic coupon codes" · "license key derived from the order"

## Realtime, WebSocket & SSE

- **WebSocket upgrade accepted with no authentication on the handshake** `ws-upgrade-no-auth-check` · crit
  "realtime updates, no login needed" · "connect to the websocket and you get live data" · "open websocket endpoint"
- **No Origin validation on the WS handshake (cross-site WebSocket hijacking)** `ws-no-origin-check-cswsh` · crit
  "realtime works automatically with your login cookie" · "cookie-based auth for the websocket" · "embeddable widget connects to our socket"
- **Realtime subscription to a table with no row-level authorization (RLS bypass via the socket)** `realtime-subscribe-rls-off-table` · crit
  "live updates streamed to every client" · "subscribe to the table and get changes in realtime" · "RLS off for now, the frontend subscribes directly"
- **Durable Object / serverless WebSocket accepts the socket with no token verification** `durable-object-socket-no-token-check` · crit
  "realtime rooms on Durable Objects" · "connect to wss://worker.dev/room/<id>" · "each room is a Durable Object, just pass the room id"
- **WebSocket trusts the session cookie alone (no bearer token / CSRF defense)** `ws-cookie-only-auth-no-token` · high
  "uses your existing login session for realtime" · "the socket just picks up your cookie" · "single sign-on cookie shared across subdomains, realtime included"
- **Broadcast/Presence channel that should be private is public (no channel authorization)** `realtime-broadcast-presence-public-channel` · high
  "presence shows who's online to everyone" · "broadcast cursors/typing to the channel" · "join any room by id"
- **No per-message authorization (connection authenticated once, every message trusted)** `ws-no-per-message-authz` · high
  "send a join message with the room id" · "the socket multiplexes all your channels" · "subscribe to any topic over the same connection"
- **Server-Sent Events stream with no authentication or per-stream authorization** `sse-endpoint-no-auth` · high
  "live updates via server-sent events, no login" · "subscribe to /events for realtime" · "open SSE stream of changes"
- **No rate limit or message-size cap on WebSocket messages** `ws-no-rate-limit-messages` · med
  "no rate limits, hammer it all you want" · "send as many messages as you like" · "realtime with no throttling"
- **WS/SSE auth token passed in the URL query string (logged, cached, referer-leaked)** `ws-token-in-url-logged` · med
  "pass your token in the websocket URL" · "connect with ?token=<jwt>" · "the access token goes in the connection string"
- **Presence/broadcast payload leaks other users' PII or internal data to every subscriber** `ws-presence-broadcast-leaks-pii` · med
  "presence shows everyone's details" · "broadcasts the full record on change" · "realtime mirrors every column to clients"

## Business Logic, Payments, Abuse & Rate Limiting

- **Payment/SMS/POS webhook handler grants entitlements with no signature or replay protection** `webhook-no-signature-or-replay-protection` · crit
  "Stripe webhook unlocks premium" · "POS / Clover webhook" · "Twilio SMS webhook"
- **Order fulfilled / plan unlocked on the client success-redirect instead of the verified webhook (or a server-side session lookup)** `fulfill-on-client-redirect-not-webhook` · crit
  "after payment we redirect you back and unlock everything" · "on success we set you to Pro" · "Stripe Checkout, super simple, redirect and done"
- **Business-logic flaws: client-supplied price/amount, negative quantities, coupon abuse, TOCTOU double-spend** `business-logic-price-tampering-and-double-spend` · high
  "in-app purchases" · "credits / wallet / balance" · "promo codes / coupons"
- **Open email/SMS send endpoint and header injection (spam cannon / denial-of-wallet)** `unauthenticated-send-endpoint-email-sms-abuse` · high
  "invite your friends by email" · "share via email" · "contact us form"
- **OTP/SMS send endpoint with no per-recipient cap (SMS pumping / toll fraud / international premium-rate abuse)** `sms-otp-toll-fraud-pumping` · high
  "phone login / SMS OTP / passwordless via text" · "we text you a code to log in" · "Twilio Verify wired up, just plug in your number"
- **No account lockout or progressive backoff after repeated failed logins (credential stuffing)** `no-account-lockout-credential-stuffing` · high
  "unlimited login attempts" · "we never lock you out" · "no account lockout, that annoys users"
- **Rate limiter trivially bypassable: trusts client IP header, or in-memory counter resets per instance** `rate-limit-bypass-trusted-header-or-in-memory` · high
  "deployed serverless on Vercel / Cloudflare Workers / Lambda" · "in-memory rate limiting, no Redis needed" · "we trust the X-Forwarded-For from the proxy"
- **Payment/credit-granting request has no idempotency key, so a retry or double-submit double-charges or double-credits** `missing-idempotency-key-on-charge-or-credit` · high
  "tap to buy, instant" · "we just call Stripe and add the credits" · "works offline, syncs your purchases when you reconnect"
- **Webhook handler is not idempotent, so Stripe's automatic retries fulfill/credit the same event multiple times** `webhook-handler-not-idempotent-double-fulfillment` · high
  "Stripe webhook adds the credits" · "webhook marks the order paid and ships it" · "we listen for payment_succeeded and unlock"
- **Currency / minor-unit mismatch: dollars passed where cents are expected (or vice versa), or float math on money** `currency-minor-unit-confusion` · high
  "multi-currency support" · "prices in your local currency" · "we charge the cart total"
- **Refund amount, target order, or eligibility is client-controlled, enabling over-refund or refunding someone else's payment** `refund-amount-or-target-client-controlled` · high
  "self-serve refunds" · "one-click refund" · "instant refund to wallet"
- **Coupon / gift card / store credit can be applied more than once (no atomic single-use), via concurrency or replay** `coupon-credit-redeemed-more-than-once` · high
  "promo codes" · "gift cards" · "store credit / wallet"
- **Negative or zero amount/quantity accepted, flipping a charge into a credit or zeroing the total** `negative-or-zero-amount-quantity-net-credit` · high
  "send credits to a friend" · "split the bill" · "adjust quantities in the cart"
- **Stripe (or PSP) test keys in production, or live keys in a test/dev build — money path silently fake or real in the wrong place** `stripe-test-live-key-environment-mismatch` · high
  "just paste your Stripe key in .env" · "test keys included so it runs out of the box" · "same config for dev and prod"
- **Charged amount and fulfilled value computed from different sources, so client can pay for one thing and receive another** `amount-charged-decoupled-from-amount-fulfilled` · high
  "we pass the plan in metadata" · "checkout takes the amount and the items" · "pick your tier at checkout"
- **Unbounded pagination / limit parameter enables full-table scrape and DoS** `unbounded-pagination-limit-scrape` · med
  "fetch all records in one call" · "pass ?limit= to control page size" · "no pagination, returns the full list"
- **No idempotency key on costly/billable operations (double-submit charges, duplicate sends, race double-spend)** `no-idempotency-on-costly-operation` · med
  "click to buy / one-tap checkout" · "we retry failed requests automatically" · "submit the form to create the order"
- **GraphQL query depth/complexity/alias-count unbounded (single-request DoS)** `graphql-depth-complexity-unbounded` · med
  "full GraphQL API, query anything" · "deeply nested relations supported" · "no query restrictions"
- **Account enumeration via response differences (status code, message, or timing) on login/reset/signup** `user-enumeration-timing-status-difference` · med
  "tells you if the email is already taken" · "clear error messages so users know what went wrong" · "helpful login errors"
- **Expensive search/export/report/image-gen endpoint with no per-user quota or concurrency cap** `expensive-search-export-no-quota` · med
  "export your whole dataset anytime" · "unlimited search" · "generate reports/PDFs on demand"
- **Captcha/Turnstile rendered on the form but never verified server-side (or verifiable bypass)** `captcha-present-but-not-enforced` · med
  "protected by Turnstile / reCAPTCHA" · "bot protection on signup" · "we added a captcha to stop spam"
- **Public content/write endpoint (comments, reviews, waitlist, uploads) with no auth, captcha, or rate limit** `public-write-endpoint-no-throttle-spam` · med
  "open comments, no signup needed" · "anyone can leave a review" · "public submission form"
- **Password-reset / magic-link / resend-verification flood (mail-bomb a victim, mailer-cost abuse)** `password-reset-flood-and-resend-abuse` · med
  "resend the link as many times as you need" · "magic-link login" · "we email you a reset link"
- **Free trial / signup credit / referral bonus farmable with throwaway accounts or self-referral** `free-trial-referral-signup-bonus-abuse` · med
  "free credits when you sign up" · "invite friends, you both get credits" · "no credit card required free trial"
- **Authorization captured for the wrong amount, never captured, or fulfilled on authorization without capture** `capture-auth-mismatch-or-capture-skipped` · med
  "we authorize now and charge later" · "add a tip after your ride/order" · "pre-authorization hold"

## Mobile, Privacy & Vibe-Coded Defaults

- **Mobile insecure config: exported components, unsafe deep links, WebView bridge, cleartext traffic** `mobile-platform-attack-surface` · high
  "deep linking" · "custom URL scheme" · "in-app browser / WebView"
- **AI-scaffold (Lovable/Bolt/v0/Replit/Cursor) insecure default config and auth stubs left in** `vibe-coded-scaffold-insecure-defaults` · high
  "built with Lovable / Bolt / v0 / Replit Agent / Cursor" · "auth coming soon" · "demo mode"
- **Auth tokens / secrets in AsyncStorage / SharedPreferences / NSUserDefaults instead of Keychain/Keystore** `tokens-in-insecure-local-storage` · high
  "tokens stored in AsyncStorage for convenience" · "we persist the session in local storage" · "keep you logged in across restarts"
- **Cleartext (HTTP) traffic allowed app-wide** `cleartext-http-traffic-allowed` · high
  "API runs over http for now" · "disable ATS so it works" · "set NSAllowsArbitraryLoads to true"
- **Exported Android component (activity/service/receiver/provider) with no permission guard** `exported-component-no-permission` · high
  "other apps can launch our screens" · "integrate via intent" · "trigger sync with a broadcast"
- **Deep-link / universal-link hijacking and unvalidated deep-link parameters** `deep-link-unvalidated-params` · high
  "magic-link opens the app and logs you in" · "deep linking / custom URL scheme" · "share links that jump into the app"
- **WebView JavaScript bridge (addJavascriptInterface / message handler) exposed to untrusted content** `webview-javascript-bridge-untrusted` · high
  "in-app browser / WebView" · "native bridge to the web dashboard" · "we load our web app inside the shell"
- **Debuggable build flag left on in a shipped/release app** `debuggable-build-shipped` · high
  "debug build for testing" · "sideload the debug apk" · "attach a debugger to inspect"
- **Dotenv package bundles .env file into the app binary** `flutter-dotenv-secrets-in-bundle` · high
  "uses dotenv for API keys" · "loads secrets from .env at runtime"
- **PII over-collection and session-replay / analytics leakage (no masking, no deletion path)** `pii-privacy-exposure-and-analytics-leakage` · med
  "session replay" · "we record user sessions" · "full analytics"
- **No certificate pinning on a high-value mobile app (network MITM)** `no-certificate-pinning` · med
  "works on any network" · "point it at your own backend URL" · "use a proxy like Charles/mitmproxy to inspect API calls"
- **Sensitive screens cached in app-switcher snapshots and secrets leaked to the clipboard** `sensitive-screen-snapshot-and-clipboard-leak` · med
  "copy your API key / seed phrase to clipboard" · "tap to copy your token" · "shows your recovery phrase on screen"
- **allowBackup=true lets app data (incl. tokens) be extracted via adb backup** `android-backup-data-extraction` · med
  "your data is backed up automatically" · "restore your session on a new phone" · "cloud backup of app data"
- **Custom URL scheme deep link hijackable by any installed app** `deep-link-scheme-hijackable` · med
  "uses deep links for auth callback" · "redirect URI uses custom scheme"
- **No root/jailbreak or integrity awareness in a high-risk app** `no-root-jailbreak-awareness-high-risk` · low
  "works on rooted/jailbroken devices" · "no device restrictions" · "runs anywhere including emulators"
- **Tapjacking: sensitive actions with no overlay protection** `tapjacking-overlay-no-protection` · low
  "one-tap confirm" · "quick approve payments" · "frictionless checkout"

## Desktop Apps & Browser Extensions

- **Electron renderer with nodeIntegration:true and contextIsolation:false** `electron-nodeintegration-no-contextisolation` · crit
  "we enable nodeIntegration so the UI can touch the filesystem directly" · "renderer has full Node access for convenience" · "turned off contextIsolation to make our React app talk to the main process easily"
- **Electron loads a remote/untrusted URL into a privileged BrowserWindow** `electron-loads-remote-or-untrusted-url` · crit
  "Electron app loads our web dashboard directly" · "it's just our website wrapped in Electron" · "points at app.oursite.com so updates are instant, no rebuild"
- **Overbroad ipcMain handler with no argument validation (renderer-to-main privilege escalation)** `electron-overbroad-ipc-handler` · crit
  "the renderer can ask main to read or write any file" · "generic IPC bridge so the UI can call any backend function" · "we expose ipcRenderer directly to the page for flexibility"
- **Auto-updater without signature verification or over insecure transport** `electron-unsigned-or-unverified-autoupdater` · crit
  "auto-updates from our S3 bucket / our server" · "the app pulls the latest build on launch" · "we don't code-sign yet, updates just download and install"
- **enableRemoteModule / @electron/remote exposing main-process objects to the renderer** `electron-enable-remote-module` · high
  "uses the remote module so the UI can call main-process APIs directly" · "enabled @electron/remote for convenience"
- **shell.openExternal / shell.openPath on renderer- or content-supplied input** `electron-shell-openexternal-untrusted` · high
  "external links open in the user's browser automatically" · "clicking a link in the app just opens it" · "we hand every link to the OS to open"
- **API keys / secrets bundled in the ASAR archive (it is not encrypted)** `electron-secrets-in-asar` · high
  "API key is bundled in the app so it works offline" · "secret is safe, it's compiled into the binary" · "we ship the key inside the asar, users can't see it"
- **webSecurity:false or allowRunningInsecureContent in BrowserWindow** `electron-websecurity-disabled` · high
  "disabled webSecurity so we can load local files / cross-origin assets" · "turned off CORS in the desktop app" · "allow mixed content so http resources load"
- **Tauri overly broad allowlist / capability scope (fs, shell, http)** `tauri-overbroad-allowlist-scope` · high
  "enabled the full fs and shell allowlist for convenience" · "the frontend can read/write anywhere on disk" · "we allow shell execute so the UI can run commands"
- **Browser extension requests <all_urls> host permissions / broad content-script matches** `ext-overbroad-host-permissions` · high
  "works on every site automatically" · "we inject on all pages so you never have to enable it" · "reads the page content wherever you browse"
- **Extension message/connect listener with no sender or origin validation** `ext-message-listener-no-sender-check` · high
  "any page can talk to the extension" · "the website communicates with the extension via postMessage" · "we expose a messaging API web pages can call"
- **Extension executes remote/eval'd code (CSP-bypassing, banned in MV3)** `ext-remote-code-or-eval-mv3` · high
  "loads its logic from our server so we can update without a store review" · "remote-configurable scripts" · "we eval the rules we fetch from the backend"
- **Auth tokens / secrets stored in chrome.storage or localStorage unencrypted** `ext-tokens-in-unencrypted-storage` · high
  "tokens stored in chrome.storage for convenience" · "we keep the API key in local storage so it persists" · "auth token saved in the extension storage, no expiry"
- **Over-broad web_accessible_resources exposing extension internals / fingerprinting** `ext-web-accessible-resources-overbroad` · med
  "all our assets are web-accessible so pages can load them" · "the injected widget is reachable from any site" · "we expose the bridge script to web pages"
- **Content script siphons page data (DOM, forms, keystrokes) to the extension/background or a remote host** `ext-content-script-leaks-page-data` · med
  "we read the page so we can enhance it (and send it to our API)" · "captures form data to help autofill" · "analytics include the pages you visit"

## AI / LLM / Agent App Security

- **Insecure output handling: raw LLM output flows into eval/SQL/shell/path/fetch/redirect** `insecure-output-handling-llm-into-sink` · crit
  "the AI writes and runs the query" · "natural language to SQL" · "the agent generates and executes code"
- **Agent reads attacker-controlled inbound (email/calendar/issues) and holds autonomous write/send/purchase tools** `agent-untrusted-inbound-autonomous-outbound` · crit
  "auto-triages your inbox" · "replies to emails for you" · "schedules meetings automatically"
- **Lethal trifecta co-located in one agent (private data + untrusted content + egress)** `agent-lethal-trifecta-colocation` · crit
  "reads your email and can browse the web and send messages" · "fully autonomous assistant with web access and send"
- **LLM / RAG output rendered as HTML or markdown without sanitization (AI-app stored XSS)** `llm-output-rendered-unsanitized-xss` · high
  "renders markdown responses" · "rich formatted AI replies" · "supports markdown / images / links in chat"
- **Data exfiltration via auto-loaded markdown image / link in the agent chat surface** `prompt-injection-markdown-image-exfil` · high
  "agent can browse / read your email / read tickets / read docs" · "renders images inline in chat" · "indirect / retrieved content feeds the model"
- **Persistent agent memory poisoned by injected content (cross-session prompt injection)** `agent-memory-context-poisoning` · high
  "remembers across sessions" · "long-term memory" · "learns from your conversations"
- **RAG ingestion poisoning and cross-tenant vector retrieval (semantic IDOR)** `rag-ingestion-poisoning-and-cross-tenant-retrieval` · high
  "upload your documents and chat with them" · "crawl any URL into the knowledge base" · "shared knowledge base"
- **Denial-of-wallet: unbounded agent iterations, no token/cost budget, recursive sub-agents** `denial-of-wallet-unbounded-agent-loops` · high
  "autonomous agent" · "runs until the task is done" · "self-reflecting / self-correcting loop"
- **LLM used as a security gate (moderation/authz/approval) bypassable by prompt injection** `llm-as-judge-authorization-bypass` · high
  "AI moderation" · "AI decides who gets access" · "automated approval"
- **Untrusted / unpinned AI model artifacts and SDKs pulled at runtime (model supply chain)** `ai-model-artifact-supply-chain` · high
  "downloads the latest model on first run" · "pulls weights from Hugging Face" · "uses a community fine-tune"
- **System prompt / model-config leakage and secrets embedded in prompt templates** `system-prompt-and-model-config-leakage` · med
  "customize the system prompt" · "edit the prompt in the app" · "prompt is configurable client-side"

## MCP Server Security

- **MCP/agent tool shells out with model- or caller-supplied arguments** `mcp-tool-shell-passthrough` · crit
  "gives the agent a shell / terminal tool" · "run any command via MCP" · "execute code the model writes"
- **MCP tool eval()/exec()/new Function() on a model-supplied param** `mcp-tool-eval-model-arg` · crit
  "code interpreter" · "run python the model writes" · "evaluate expressions"
- **MCP fetch/URL tool with no SSRF allowlist or driven by prompt injection** `mcp-fetch-tool-no-ssrf-guard` · crit
  "fetch any URL" · "give it a link and it reads the page" · "web scraper tool"
- **MCP file read/write/resource tool with no path confinement** `mcp-file-tool-no-confinement` · crit
  "read/write any file" · "give it a path and it reads it" · "filesystem access, full disk access"
- **MCP DB tool builds SQL from model strings / runs arbitrary SQL** `mcp-sql-tool-injection` · crit
  "ask your database in natural language" · "runs SQL the model writes" · "query any table"
- **MCP tool deserializes untrusted input (pickle/yaml/torch.load)** `mcp-deserialization-in-tool-input` · crit
  "load saved sessions" · "import a model/state file" · "restore from a blob you provide"
- **MCP server bound to a network port with no auth / wildcard CORS** `mcp-unauthenticated-network-server` · crit
  "expose over the network" · "remote MCP server, no auth needed" · "just point your client at the URL"
- **MCP server package with import-time payload or provenance mismatch** `mcp-server-package-provenance` · crit
  "install our MCP server: npx some-unofficial-mcp"
- **MCP server holds broad creds the caller shouldn't reach (confused deputy)** `mcp-confused-deputy-broad-creds` · high
  "drop in your API key and it can do everything" · "uses your admin token for everything" · "one key, full access"
- **OAuth token passthrough / audience confusion** `mcp-oauth-token-passthrough` · high
  "bring your own token" · "forwards your token to the API" · "reuses your existing OAuth session"
- **Tool returns secrets/env/full creds into the model context** `mcp-secrets-returned-or-env-dump` · high
  "inspect your environment" · "debug tool shows config" · "dumps all settings"
- **Untrusted external content returned straight into context (indirect prompt injection)** `mcp-prompt-injection-via-tool-output` · high
  "reads web pages and acts on them" · "summarizes emails/issues automatically" · "agent reads external content and takes actions"
- **Tool description/name/metadata carries injected instructions to the model** `mcp-injectable-tool-description` · high
  "dynamic tool descriptions" · "descriptions fetched from a server" · "our MCP enhances Claude's behavior automatically"
- **Tool definitions mutate after client approval (rug pull)** `mcp-rug-pull-tool-redefinition` · high
  "auto-updating tools" · "tools update themselves" · "pulls latest tool definitions on launch"
- **Irreversible/destructive action tools fire with no human gate or cost limit** `mcp-destructive-tool-no-gate` · high
  "fully autonomous, no confirmations needed" · "the agent just does it" · "unlimited calls / blast emails / scrape at scale"
- **MCP server disables TLS verification on upstream calls** `mcp-tls-verify-disabled` · high
  "ignore SSL errors" · "works with self-signed by default" · "disable cert checks for convenience"
- **Local HTTP/SSE MCP server with no DNS-rebinding protection** `mcp-localhost-http-dns-rebinding` · high
  "runs a local MCP server on localhost"
- **Generic tool names enable shadowing of trusted tools across servers** `mcp-tool-name-shadowing` · med
  "replaces your other tools" · "use this instead of the built-in" · "takes priority over other MCP servers"
- **Tool params lack schema/type validation and allowlisting** `mcp-missing-param-validation` · med
  "flexible inputs" · "accepts any value" · "no strict schema"
- **Local stdio server assumes caller is trusted, exposes raw OS power** `mcp-stdio-trusts-local-as-safe` · med
  "local only so no security needed" · "trusted environment" · "runs as you, full access"
- **Server abuses sampling/elicitation to exfiltrate or harvest secrets** `mcp-elicitation-sampling-abuse` · med
  "asks you for your password when needed" · "collects credentials interactively" · "server can prompt the model on its own"
- **Tool returns unbounded content into context** `mcp-tool-output-unbounded` · low
  "reads entire files" · "returns the full dataset" · "no size limits"

## Claude Plugins, Skills, Hooks & Agents

- **Hook/skill script reads env, ~/.ssh, ~/.aws, keychains and exfiltrates** `hook-exfiltrates-env-or-credentials` · crit
  "telemetry/usage analytics enabled by default with no opt-out" · "phones home to check for updates / license" · "sends your project context to our servers"
- **Skill/command/hook pipes remote content into a shell (curl|bash, iwr|iex)** `skill-hook-curl-bash-remote` · crit
  "install with one line: curl https://... | bash" · "quick start: paste this into your terminal" · "the skill downloads and runs the latest helper automatically"
- **Hook/skill downloads a payload then executes it (two-stage RCE)** `hook-fetches-then-executes` · crit
  "downloads the latest rules/helper on startup" · "self-bootstrapping" · "fetches plugins/extensions on demand"
- **Messaging/channel plugin lets inbound messages drive access, install, or shell** `channel-message-drives-privileged-action` · crit
  "control Claude Code from your phone / chat" · "approve pairings by replying to the message" · "auto-responds to anyone who messages"
- **Hidden / override instructions embedded in SKILL.md, agent, or command body** `prompt-injection-hidden-instructions-in-skill` · high
  "description and body disagree about what the skill does" · "works invisibly / runs silently without bothering you" · "claims read-only but body tells the model to write/commit"
- **Invisible / control-character payload in an instruction or tool-metadata file** `invisible-unicode-in-instructions` · high
  "invisible by construction; only a byte/codepoint scan reveals it"
- **Slash command / skill grants Bash(*) or unrestricted allowed-tools** `command-allowed-tools-bash-wildcard` · high
  "full shell access for maximum flexibility" · "no permission prompts, just works" · "runs any command you need"
- **settings.json auto-approves dangerous tools or widens the permission allow list** `settings-json-widens-permissions` · high
  "adds recommended permissions so you stop getting prompted" · "open by default for easy setup" · "disables confirmation dialogs"
- **Skill/command instructs the model to bypass permissions or run in YOLO/bypass mode** `skill-instructs-disable-safety` · high
  "runs without interruptions / no annoying prompts" · "YOLO mode for speed" · "skip confirmations to go faster"
- **Hook silently approves dangerous tool calls or suppresses other validators** `hook-tampers-security-tooling` · high
  "auto-approves safe-looking commands" · "removes friction from the permission system" · "streamlines confirmations"
- **SessionStart hook writes attacker-controlled env vars via $CLAUDE_ENV_FILE** `hook-persists-env-via-claude-env-file` · high
  "sets up your environment automatically on session start" · "configures proxy / mirror for faster installs" · "adds helpers to your PATH"
- **Hook/skill writes outside the plugin/project root (rc files, autostart, cron)** `plugin-writes-outside-plugin-root` · high
  "installs a background service so it keeps running" · "adds itself to startup" · "sets up a cron job for you"
- **Agent/skill rewrites its own plugin files, settings.json, hooks, or MCP config** `agent-self-modifies-config` · high
  "learns and updates its own configuration" · "self-installing, sets up the hooks it needs" · "persists across sessions automatically"
- **Command/skill body interpolates $ARGUMENTS or fetched output into !`...` shell substitution** `command-arguments-into-shell-substitution` · high
  "pass any arguments, we run them for you" · "summarize this GitHub issue and act on it" · "pulls live context from the web / issues / PRs automatically"
- **Plugin package runs arbitrary code via npm/pip lifecycle (postinstall) scripts** `plugin-postinstall-script` · high
  "just npm install and you're done, it sets everything up" · "the installer configures your environment" · "no mention of what the install step does"
- **Plugin ships a prebuilt binary or obfuscated/minified script as a hook/MCP entrypoint** `plugin-bundles-binary-or-obfuscated` · high
  "precompiled for performance" · "bundled binary, no dependencies" · "no source for the thing the hook executes"
- **Instructions tell users to add an untrusted marketplace or auto-install/auto-approve plugins** `untrusted-marketplace-or-autoinstall` · high
  "add my marketplace and install everything with one command" · "auto-approve everything for smooth UX" · "just run npx some-server and approve all tools"
- **Plugin .mcp.json points at a remote/attacker server or forwards host secrets** `plugin-mcp-remote-or-secret-forwarding` · high
  "connects to our hosted MCP endpoint automatically" · "adds an MCP server in the background" · "automatically uses your API keys"
- **Subagent grants Bash/WebFetch/all-tools when it only needs read access** `agent-tools-overbroad` · med
  "the agent can do anything it needs" · "full toolset for thorough analysis" · "read-only but granted shell/network"
- **PreToolUse/PostToolUse hook runs an opaque script on every tool and forwards tool I/O** `hook-runs-on-every-tool-unscoped` · med
  "monitors everything you do" · "logs all tool calls" · "runs on every action for full coverage"
- **Skill description engineered to over-trigger and shadow legitimate skills** `skill-description-overbroad-trigger` · med
  "triggers on everything for maximum helpfulness" · "always loads first" · "replaces your other tools"

## AI Coding-Agent & IDE-Config Trust

- **Committed agent project-config runs code / redirects the API on clone-open** `claude-project-config-clone-open-rce` · high
  "clone and run" · "just open in Claude Code" · "no setup, it configures itself"
- **Committed mcp.json auto-launches an unpinned / secret-forwarding server on open** `committed-mcp-config-autolaunch` · high
  "MCP server included" · "auto-connects when you open the repo"
- **Rules File Backdoor: injected directives in a cross-tool instruction file** `rules-file-backdoor-cross-tool` · high
  "drop in our .cursorrules" · "use our recommended AI rules file"
- **VS Code tasks.json runs code on folder open** `vscode-tasks-auto-execute` · high
  "auto-runs setup on open" · "tasks run automatically when you open the project"

## Dependencies & Supply Chain

- **Install lifecycle script (pre/postinstall) fetching or running remote code** `npm-postinstall-remote-code` · crit
  "runs a setup step automatically on install" · "no build step needed, our postinstall handles everything" · "downloads the binary for your platform during npm install"
- **Long-lived registry/publish tokens committed or stored in repo** `committed-registry-publish-token` · crit
  "set your npm token in .npmrc and commit it" · "publishing works out of the box, token is in the repo" · "add NPM_TOKEN to the workflow shown as a literal"
- **README install instructions pipe a remote script straight to a shell** `curl-bash-install-instructions` · high
  "Quick install: curl -fsSL https://example.com/install.sh | sudo bash" · "One-line install" · "To get started, just run this in your terminal followed by a curl pipe"
- **No lockfile committed (floating dependency resolution)** `no-lockfile` · high
  "run npm install to get the latest dependencies" · "we always pull the newest versions" · "no lockfile, keeps things simple"
- **GitHub Actions / third-party action pinned to a mutable ref instead of a SHA** `unpinned-github-actions-mutable-ref` · high
  "just add this to your workflow: uses: foo/bar@main" · "copy our GitHub Action with a tag-pinned snippet" · "always uses the latest version of the action automatically"
- **Git/URL/tarball/MCP dependency pinned to a branch or fetched unpinned at runtime** `git-or-unpinned-remote-dependency` · high
  "install from our GitHub directly for the latest" · "always runs the latest version" · "tools update automatically from our server"
- **Dependencies with known CVEs / advisories pinned in** `known-vulnerable-deps` · high
  "battle-tested stable stack with years-old version badges" · "we don't update dependencies unless something breaks" · "accepts YAML/XML/serialized input with an old parser pinned"
- **Typosquat / dependency-confusion / brandjacking risk in dep names** `typosquat-dependency-confusion` · high
  "install our private package: npm i mycompany-utils" · "point npm at our internal registry" · "monorepo with shared internal packages (no scoping note)"
- **Vendored minified blob of unverifiable origin or third-party CDN script without SRI** `vendored-or-cdn-blob-no-sri` · high
  "bundled dependencies included for convenience" · "vendored a patched copy of <lib> with no diff" · "just drop in our CDN script tag"
- **Critical dependency sourced from a personal CDN, gist, or pastebin** `alternate-cdn-gist-as-source-of-truth` · high
  "grab the helper from this gist" · "sourced from my personal CDN" · "import directly from the URL, no install"
- **.npmignore / files gaps publishing secrets or source to the registry** `secrets-shipped-to-registry` · high
  "publish with npm publish and a repo that keeps .env at the root" · "we ship the whole project to npm"
- **Package-manager config weakens registry TLS/trust** `package-manager-config-weakens-trust` · high
  "if install fails, set strict-ssl false" · "add --trusted-host to pip" · "use our http registry mirror"
- **Imported package absent from the lockfile / registry (slopsquatting)** `slopsquat-import-not-in-lockfile` · high
  "generated with v0/Bolt/Lovable/Cursor" · "AI-scaffolded"
- **Wide/wildcard version ranges allowing arbitrary future code** `overly-broad-version-ranges` · med
  "uses latest of everything" · "depends on the main branch of <lib> for newest features" · "always up to date with upstream"
- **Abandoned / unmaintained dependency in a security-critical path** `abandoned-unmaintained-critical-dep` · med
  "stable, hasn't needed changes in years" · "links to archived/read-only dependency repos" · "pinned an old version because the new one broke us"
- **Container base image / build deps unpinned** `docker-base-image-unpinned` · med
  "FROM node:latest shown in docs" · "always builds on the newest base image" · "docker build, that's it with an unpinned Dockerfile"
- **Releases published without provenance / signatures / checksums** `no-provenance-unsigned-releases` · med
  "download the binary from releases (no checksum/signature instructions)" · "trusted, just run the downloaded exe"
- **Build config executes untrusted plugins/loaders fetched per-build** `build-plugin-arbitrary-config-exec` · med
  "extends our shared config automatically" · "build pulls the latest plugin set" · "no config needed, presets are fetched"
- **Lockfile present but install doesn't enforce it / drift hides unreviewed versions** `transitive-integrity-not-enforced` · low
  "just npm install and go" · "if install complains, just delete the lockfile and reinstall" · "we don't really maintain the lockfile"
- **No automated dependency / advisory monitoring configured** `no-dependency-update-automation` · low
  "we update dependencies manually when we remember" · "no security policy or contact for vulnerabilities" · "stable, rarely touched with no monitoring"

## CI/CD & Infrastructure

- **Untrusted GitHub event field interpolated into a run: shell** `actions-expression-injection-run` · crit
  "auto-labels issues / PRs" · "comments on your PR automatically" · "greets new contributors / triages issues with a bot"
- **pull_request_target/workflow_run checks out and runs untrusted PR code** `pull-request-target-checkout-untrusted` · crit
  "runs CI on forked PRs with full secrets" · "labels/comments on external PRs" · "works on PRs from anyone, no maintainer approval needed"
- **CI AI-agent step fed untrusted event text with write/secret scope** `ai-agent-ci-untrusted-event-context` · crit
  "@claude will respond to issues and PRs" · "mention the bot to run the agent"
- **GITHUB_TOKEN / workflow permissions are write-all** `github-token-write-all` · high
  "the bot pushes commits / creates releases / opens PRs for you" · "zero-config CI, no token setup"
- **Attacker-controlled content written to GITHUB_ENV / GITHUB_PATH / GITHUB_OUTPUT** `github-env-path-injection` · high
  "derives build vars from the branch name / PR body" · "dynamic matrix from issue input"
- **Self-hosted runner exposed to public/fork PRs with secret/network access** `self-hosted-runner-public-pr` · high
  "CI runs on our own hardware / self-hosted runners" · "open to community PRs (public repo with self-hosted CI)" · "CI has access to deploy/prod secrets"

