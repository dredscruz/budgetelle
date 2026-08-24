// Recovery-key authentication: proves knowledge of the personal Recovery Key
// (SHA-256 hash — the key itself never leaves the device) and returns the
// encrypted vault doc so the client can decrypt it locally and re-key under
// a new password. Zero-knowledge: the server cannot decrypt anything.
const { kvGet } = require('./_lib/store');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  let body = '';
  req.on('data', c => { body += c; if (body.length > 5_000) req.destroy(); });
  req.on('end', async () => {
    try {
      const { email, recovHash } = JSON.parse(body);
      const em = (email || '').toLowerCase();
      if (!EMAIL_RE.test(em) || !recovHash || typeof recovHash !== 'string' || recovHash.length > 200) {
        return res.status(400).json({ error: 'Bad request' });
      }
      const stored = await kvGet('budgetelle.recovhash.' + em);
      if (!stored || stored !== recovHash) return res.status(401).json({ error: 'Recovery key mismatch' });
      const doc = await kvGet('budgetelle.vault.' + em);
      if (!doc) return res.status(404).json({ error: 'No cloud vault' });
      // rate-limit-friendly: no data beyond the encrypted blob is exposed
      res.status(200).json({ doc });
    } catch { res.status(400).json({ error: 'Bad request' }); }
  });
};
