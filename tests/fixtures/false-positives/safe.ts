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
