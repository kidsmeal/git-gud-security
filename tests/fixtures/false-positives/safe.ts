// False-positive fixtures: none of these should fire

// env var reads (not hardcoded)
const key = process.env.API_KEY;
const secret = import.meta.env.VITE_API_KEY;
const dbUrl = process.env.DATABASE_URL;

// publishable / anon keys are safe to expose
const supabaseUrl = "https://abc.supabase.co";
const supabaseAnonKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test";

// placeholder / example values
const api_key = "your-api-key-here";
const secret_key = "changeme";
const password = "placeholder";
const token = "xxx-not-real";
const dummy = "example_key_for_testing";

// comments about secrets (not actual secrets)
// This is where we store the API key from the env

// localhost DB connections are fine
const devDb = "postgres://user:password@localhost:5432/dev";
const localDb = "postgres://admin:password@127.0.0.1:5432/test";

// safe cookie with secure flags
res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "strict" });

// 0.0.0.0 mentioned but not bound: help text, comparisons, display mapping
const help = `  server --host 0.0.0.0      # Bind to all interfaces`;
function displayHost(host: string) {
  if (host === "0.0.0.0") return "127.0.0.1";
  return host;
}
// bind to 0.0.0.0 only when the operator passes --host explicitly
console.warn("unauthenticated HTTP is bound to 0.0.0.0; prefer loopback");

// operator-facing log lines, not tool result text addressed to the model
console.log("Learn more at https://example.com/docs");

// lockfile-shaped integrity hash is not a secret
const lock = { "integrity": "sha512-5f1laC0SlIR0yDbFCd8acUhvJIag6N3zC5P7oUPN6wX0aOma+uKJ0wBDH5aq7I1PVI2ttTlhJwzwRIBnLiSGEg==" };
