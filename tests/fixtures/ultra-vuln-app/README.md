# billing-api (test fixture)

DELIBERATELY VULNERABLE. This is a fixture for verifying git-gud-security's ultra mode against
trace-tier holes (IDOR, SSRF, privilege escalation, command injection). Do not deploy it, do not
copy from it. Every route below is here to be found.

A tiny Express billing API: invoices, orders, refunds, a link-preview helper, and a health ping.
