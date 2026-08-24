// Credential-based auth for email/password accounts (no Google session).
// Client sends bt-email / bt-salt / bt-hash headers; we check them against
// the account record claimed in the KV store. The hash is a PBKDF2-SHA256
// verifier derived from the password — the server never sees the password.
const { kvGet } = require('./store');

async function credAuth(req) {
  const email = (req.headers['bt-email'] || '').toLowerCase();
  const salt = req.headers['bt-salt'] || '';
  const hash = req.headers['bt-hash'] || '';
  if (!email || !salt || !hash) return null;
  const rec = await kvGet('budgetelle.acct.' + email);
  if (!rec) return null;
  let r;
  try { r = JSON.parse(rec); } catch { return null; }
  if (r.salt !== salt || r.hash !== hash) return null;
  return { account: email };
}

module.exports = { credAuth };
