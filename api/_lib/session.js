// Shared helpers for Budgetelle serverless functions
const crypto = require('crypto');

function b64url(buf) { return Buffer.from(buf).toString('base64url'); }

function sessionSecret() {
  return process.env.SESSION_SECRET || process.env.GOOGLE_CLIENT_SECRET || 'budgetelle-dev-secret';
}

function sign(payload) {
  const body = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', sessionSecret()).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function verify(token) {
  if (!token || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expect = crypto.createHmac('sha256', sessionSecret()).update(body).digest('base64url');
  if (sig !== expect) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (p.exp && Date.now() > p.exp) return null;
    return p;
  } catch { return null; }
}

function cookieHeader(name, value, maxAge) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(c => {
    const i = c.indexOf('='); if (i > -1) out[c.slice(0, i).trim()] = c.slice(i + 1).trim();
  });
  return out;
}

const SITE = process.env.SITE_URL || 'https://budgetelle.vercel.app';
function oauthConfigured() { return !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET); }

module.exports = { sign, verify, cookieHeader, parseCookies, SITE, oauthConfigured };
