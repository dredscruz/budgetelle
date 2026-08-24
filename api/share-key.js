// Account unlock-key share.
// Auth: Google session cookie, OR a signed invite capability token
//       (header 'bt-cap' or ?cap=) from a redeemed household link.
const { verify, parseCookies } = require('./_lib/session');
const { kvGet, kvSet } = require('./_lib/store');

function auth(req, res) {
  const s = verify(parseCookies(req).bt_session);
  if (s && s.email) return { account: s.email.toLowerCase() };
  const url = new URL(req.url, 'http://x');
  let capRaw = req.headers['bt-cap'] || url.searchParams.get('cap');
  if (capRaw && capRaw.includes('.')) capRaw = capRaw.split(',').pop();
  const cap = verify(capRaw);
  if (cap && cap.v === 1 && cap.for) return { account: cap.for, member: cap.mid };
  res.status(401).json({ error: 'Sign in or use an invite link' });
  return null;
}

module.exports = async (req, res) => {
  const a = auth(req, res); if (!a) return;
  const acct = a.account;

  if (req.method === 'GET') {
    return res.status(200).json({ pw: await kvGet('budgetelle.key.' + acct) });
  }

  if (req.method === 'POST') {
    const s = verify(parseCookies(req).bt_session);
    if (!s || !s.email || s.email.toLowerCase() !== acct) {
      return res.status(403).json({ error: 'Only the owner can update the key' });
    }
    let body = '';
    req.on('data', c => { body += c; if (body.length > 5_000) req.destroy(); });
    req.on('end', async () => {
      try {
        const { pw } = JSON.parse(body);
        if (!pw || typeof pw !== 'string' || pw.length < 20 || pw.length > 200) return res.status(400).json({ error: 'Bad key' });
        await kvSet('budgetelle.key.' + acct, pw);
        res.status(200).json({ ok: true });
      } catch { res.status(400).json({ error: 'Bad request' }); }
    });
    return;
  }
  res.status(405).json({ error: 'Method not allowed' });
};
