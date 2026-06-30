// Regression for the double-finding redaction leak: a token on a line that ALSO trips a
// non-secret pattern. The secret finding redacts its own match, but a second finding's
// snippet goes through the global scrub only. If scrub doesn't cover the format, it leaks.
localStorage.setItem("sendgrid", "SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr");
