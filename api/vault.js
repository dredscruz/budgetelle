// Cloud vault: store/retrieve the encrypted vault blob.
// Auth: Google session cookie, OR a signed invite capability token
//       (header 'bt-cap' or ?cap=) issued when a household code/link is redeemed.
const { verify, parseCookies } = require('./_lib/session');
const { kvGet, kvSet } = require('./_lib/store');
const { credAuth } = require('./_lib/cred');

async function auth(req, res) {
  const s = verify(parseCookies(req).bt_session);
  if (s && s.email) return { account: s.email.toLowerCase() };
  const url = new URL(req.url, 'http://x');
  let capRaw = req.headers['bt-cap'] || url.searchParams.get('cap');
  if (capRaw && capRaw.includes('.')) capRaw = capRaw.split(',').pop(); // cookie-style header
  const cap = verify(capRaw);
  if (cap && cap.v === 1 && cap.for) return { account: cap.for, member: cap.mid };
  const cred = await credAuth(req);
  if (cred) return { ...cred, cred: true };
  res.status(401).json({ error: 'Sign in or use an invite link' });
  return null;
}

module.exports = async (req, res) => {
  const a = await auth(req, res); if (!a) return;
  if (!a.account) return res.status(401).json({ error: 'Sign in or use an invite link' });
  const mine = 'budgetelle.vault.' + a.account;

  if (req.method === 'GET') {
    return res.status(200).json({ doc: await kvGet(mine) });
  }

  if (req.method === 'POST') {
    // the account's own Google session OR matching credentials may write
    const s = verify(parseCookies(req).bt_session);
    const isOwner = s && s.email && s.email.toLowerCase() === a.account;
    const viaCred = a.cred === true;
    if (!isOwner && !viaCred) {
      return res.status(403).json({ error: 'Only the owner can update the vault' });
    }
    let body = '';
    req.on('data', c => { body += c; if (body.length > 3_000_000) req.destroy(); });
    req.on('end', async () => {
      try {
        const { doc } = JSON.parse(body);
        if (doc === '') { await kvSet(mine, ''); return res.status(200).json({ ok: true, cleared: true }); } // password reset: drop stale blob
        if (!doc || typeof doc !== 'string' || doc.length > 2_500_000) return res.status(400).json({ error: 'Bad doc' });
        await kvSet(mine, doc);
        res.status(200).json({ ok: true });
      } catch { res.status(400).json({ error: 'Bad request' }); }
    });
    return;
  }
  res.status(405).json({ error: 'Method not allowed' });
};
