// Household invites.
// POST { action:'create', memberId }   (owner session)      -> { code }
// POST { action:'redeem', code }       (anyone with code)   -> { email, mid, cap, ownerName }
//   `cap` is a signed 30-day capability token letting the bearer read the
//    owner's vault + unlock key without any Google session.
const { verify, parseCookies, sign } = require('./_lib/session');
const { kvGet, kvSet } = require('./_lib/store');
const crypto = require('crypto');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  let body = '';
  req.on('data', c => { body += c; if (body.length > 10_000) req.destroy(); });
  req.on('end', async () => {
    try {
      const { action, memberId, code } = JSON.parse(body);
      const s = verify(parseCookies(req).bt_session); // may be null — code alone authorizes

      if (action === 'create') {
        if (!s || !s.email) return res.status(401).json({ error: 'Sign in first' });
        if (!memberId) return res.status(400).json({ error: 'Missing member' });
        const c = String(crypto.randomInt(100000, 1000000)); // 6 digits
        await kvSet('budgetelle.code.' + c, JSON.stringify({
          email: s.email.toLowerCase(), mid: memberId, t: Date.now()
        }), 60 * 60 * 24 * 7); // valid 7 days
        return res.status(200).json({ code: c });
      }

      if (action === 'redeem') {
        const raw = await kvGet('budgetelle.code.' + String(code || '').trim());
        if (!raw) return res.status(404).json({ error: 'This invite has expired — ask for a new link.' });
        const d = JSON.parse(raw);
        // remember the redemption for Google-signed-in members (legacy path)
        if (s && s.email) {
          await kvSet('budgetelle.redeemed.' + s.email.toLowerCase(), d.email.toLowerCase(), 60 * 60 * 24 * 30);
        }
        const cap = sign({ v: 1, for: d.email.toLowerCase(), mid: d.mid, exp: Date.now() + 30 * 24 * 3600 * 1000 });
        return res.status(200).json({ email: d.email, mid: d.mid, cap });
      }

      res.status(400).json({ error: 'Unknown action' });
    } catch { res.status(400).json({ error: 'Bad request' }); }
  });
};
