// True-positive fixtures for secret detection patterns.
// Every value here is fake but matches the scanner's regexes.

const anthropicKey = "sk-ant-TESTFIXTURE1234567890abcdefghij";
const openaiKey = "sk-proj-TESTFIXTURE1234567890abcdefghij";
const openaiLegacy = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
const awsKey = "AKIAIOSFODNN7FIXTURE";
const githubPat = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
const githubOauth = "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
const githubPatNew = "github_pat_TESTFIXTURE1234567890ab";
const gitlabPat = "glpat-TESTFIXTURE1234567890abcdef";
const slackToken = "xoxb-1234567890-abcdefghij";
const googleKey = "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ12345";
const stripeKey = "sk_live_ABCDEFGHIJKLMNOPQRST";
const stripeRestricted = "rk_live_ABCDEFGHIJKLMNOPQRST";
const sendgridKey = "SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr";
const twilioSid = "ACgg11hh22jj33kk44mm55nn66pp7788";


const NEXT_PUBLIC_STRIPE_SECRET_KEY = "sk_live_shouldnotbehere1234";
const VITE_AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE";

const dbUrl = "postgres://admin:s3cretP4ssw0rd@db.example.com:5432/production";
const redisUrl = "redis://default:r3disP4ssword@cache.example.com:6379";

const api_key = "Bhqu9mLr4Xk8vP2nW7zT3Yf6";
const jwt_secret = "myJwtSigningSecretValueHere123";

const supabaseSecret = "sb_secret_TESTFIXTURE1234567890abcdef";
const groqKey = "gsk_TESTFIXTURE1234567890ab";
const huggingfaceKey = "hf_TESTFIXTURE1234567890ab";
const replicateKey = "r8_TESTFIXTURE1234567890ab";
const xaiKey = "xai-TESTFIXTURE1234567890ab";
const pplxKey = "pplx-TESTFIXTURE1234567890abcdefghijklmn";
const npmToken = "npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";

const privateKeyBlock = `-----BEGIN RSA PRIVATE KEY-----
MIIBogIBAAJBALRiMLAHudeSA/x3hB2f+2NRkJLA
-----END RSA PRIVATE KEY-----`;

const rejectUnauthorized = { rejectUnauthorized: false };
const curlInstall = "curl https://install.example.com/setup.sh | bash";
