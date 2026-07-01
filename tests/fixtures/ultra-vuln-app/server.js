// DELIBERATELY VULNERABLE test fixture — see README.md. Every route is here to be found.
const express = require('express');
const { execSync } = require('child_process');
const fetch = require('node-fetch');
const db = require('./db');

const app = express();
app.use(express.json());

// Naive "auth": trusts client-supplied headers, verifies nothing.
function currentUser(req) {
  return { id: req.header('x-user-id'), role: req.header('x-user-role') || 'user' };
}

// IDOR: returns any invoice by id, never checks it belongs to the caller or their tenant.
app.get('/api/invoices/:id', (req, res) => {
  const invoice = db.getInvoice(req.params.id);
  if (!invoice) return res.status(404).end();
  res.json(invoice);
});

// SSRF: fetches an arbitrary user-supplied URL with no allowlist or IP filtering.
app.get('/api/link-preview', async (req, res) => {
  const r = await fetch(req.query.url);
  res.send(await r.text());
});

// Privilege escalation: the role is read straight from a user-controlled header, so any
// caller can send x-user-role: admin and pass this check.
app.post('/api/admin/refund', (req, res) => {
  const user = currentUser(req);
  if (user.role === 'admin') {
    return res.json(db.refund(req.body.paymentId));
  }
  res.status(403).end();
});

// Command injection: user input is interpolated into a shell command.
app.get('/api/ping', (req, res) => {
  const out = execSync(`ping -c1 ${req.query.host}`);
  res.send(out.toString());
});

// Guarded route — NOT a finding. Ownership is checked before returning the object.
app.get('/api/orders/:id', (req, res) => {
  const user = currentUser(req);
  const order = db.getOrder(req.params.id);
  if (!order || order.userId !== user.id) return res.status(404).end();
  res.json(order);
});

// Hardcoded third-party secret (grep-tier; here to exercise seed-from-scan later).
const STRIPE_SECRET = 'sk_live_ABCDEFGHIJKLMNOPQRST';

app.listen(3000, () => console.log('billing-api on :3000'));
