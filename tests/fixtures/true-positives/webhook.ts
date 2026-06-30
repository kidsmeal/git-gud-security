// True-positive fixtures for webhook and MCP patterns

import Stripe from "stripe";
const event = stripe.webhooks.constructEvent(body, sig, "");

const verify_jwt = false;

import { createServer } from "http";
const server = createServer((req, res) => {
  const url = `http://localhost:${PORT}${req.url}`;
});

const mcpServer = new Server({ host: "0.0.0.0", port: 3000 });
const opts = { enableDnsRebindingProtection: false };
