// True-positive fixtures for auth patterns

import { createClient } from "@supabase/supabase-js";
const supabaseAdmin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);

const session = await supabase.auth.getSession();
const role = session.data.session?.user.user_metadata.role;
if (role === "admin") { grantAccess(); }

if (user.email === "admin@example.com") { isAdmin = true; }
if (user.role == "admin") { grantAccess(); }

res.setHeader("Access-Control-Allow-Origin", "*");
res.setHeader("Access-Control-Allow-Credentials", "true");

res.cookie("session", token, { httpOnly: false });
res.cookie("auth", value, { secure: false });

app.config["DEBUG"] = true;
DEBUG = true;

const tokenData = Math.random().toString(36).slice(2);

localStorage.setItem("access_token", token);
sessionStorage.setItem("refresh_token", refreshToken);

console.log("Request body:", req.body);
console.log("Authorization header:", req.headers.authorization);

const weakHash = md5(password);
const ecbCipher = AES.encrypt(data, key, { mode: CryptoJS.modes.ECB });
