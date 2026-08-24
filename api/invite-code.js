// Household invite codes: owner creates a 6-digit code bound to a member;
// a Google-signed-in user redeems it to open the household vault.
// POST { action:'create', memberId } -> { code }   (owner session)
// POST { action:'redeem', code }     -> { email }  (member's Google session)
const { verify, parseCookies } = require('./_lib/session');
const { kvGet, kvSet } = require('./_lib/store');
const crypto = require('crypto');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  let body = '';
  req.on('data', c => { body += c; if (body.length > 10_000) req.destroy(); });
  req.on('end', async () => {
    try {
      const { action, memberId, code } = JSON.parse(body);
      if (action === 'create') {
        const s = verify(parseCookies(req).bt_session);
        if (!s || !s.email) return res.status(401).json({ error: 'Sign in first' });
        if (!memberId) return res.status(400).json({ error: 'Missing member' });
        const code = String(crypto.randomInt(100000, 1000000)); // 6 digits
        await kvSet('budgetelle.code.' + code, JSON.stringify({
          email: s.email.toLowerCase(), mid: memberId, t: Date.now()
        }), 60 * 60 * 24 * 7); // valid 7 days
        return res.status(200).json({ code });
      }
      if (action === 'redeem') {
        const s = verify(parseCookies(req).bt_session);
        if (!s || !s.email) return res.status(401).json({ error: 'Sign in with Google first' });
        const raw = await kvGet('budgetelle.code.' + String(code || '').trim());
        if (!raw) return res.status(404).json({ error: 'Code not found or expired' });
        const d = JSON.parse(raw);
        // remember the redemption so vault/share-key endpoints allow cross-account reads
        await kvSet('budgetelle.redeemed.' + s.email.toLowerCase(), d.email.toLowerCase(), 60 * 60 * 24 * 30);
        return res.status(200).json({ email: d.email, mid: d.mid });
      }
      res.status(400).json({ error: 'Unknown action' });
    } catch { res.status(400).json({ error: 'Bad request' }); }
  });
};
