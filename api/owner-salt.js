// Owner publishes their PBKDF2 salt at sign-in (Google-session auth).
// Invited members read it ONLY with a valid invite capability token.
const { verify, parseCookies } = require('./_lib/session');
const { kvGet, kvSet } = require('./_lib/store');

module.exports = async (req, res) => {
  if (req.method === 'POST') {
    // publish: must be the account's own Google session
    const s = verify(parseCookies(req).bt_session);
    let body = '';
    req.on('data', c => { body += c; if (body.length > 5_000) req.destroy(); });
    req.on('end', async () => {
      try {
        const { email, salt } = JSON.parse(body);
        if (!s || !s.email || !email || email.toLowerCase() !== s.email.toLowerCase()) {
          return res.status(403).json({ error: 'Only the account itself can publish its salt' });
        }
        if (!salt || typeof salt !== 'string' || salt.length > 200) return res.status(400).json({ error: 'Bad salt' });
        await kvSet('budgetelle.salt.' + email.toLowerCase(), salt);
        res.status(200).json({ ok: true });
      } catch { res.status(400).json({ error: 'Bad request' }); }
    });
    return;
  }
  if (req.method === 'GET') {
    // read: only with a valid invite capability
    const url = new URL(req.url, 'http://x');
    const cap = verify(url.searchParams.get('cap'));
    if (!cap || cap.v !== 1 || !cap.for) return res.status(401).json({ error: 'Invalid invite' });
    const salt = await kvGet('budgetelle.salt.' + cap.for);
    if (!salt) return res.status(404).json({ error: 'Household not ready yet' });
    return res.status(200).json({ salt });
  }
  res.status(405).json({ error: 'Method not allowed' });
};
