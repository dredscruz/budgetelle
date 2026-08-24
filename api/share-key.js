// Account unlock-key share. GET ?email=... returns another account's key ONLY
// when the requester has redeemed a household code for it; otherwise their own.
const { verify, parseCookies } = require('./_lib/session');
const { kvGet, kvSet } = require('./_lib/store');

module.exports = async (req, res) => {
  const s = verify(parseCookies(req).bt_session);
  if (!s || !s.email) return res.status(401).json({ error: 'Not signed in' });

  if (req.method === 'GET') {
    const url = new URL(req.url, 'http://x');
    let target = url.searchParams.get('email');
    if (target) {
      target = target.toLowerCase();
      const redemption = await kvGet('budgetelle.redeemed.' + s.email.toLowerCase());
      if (redemption !== target) return res.status(200).json({ pw: null });
      return res.status(200).json({ pw: await kvGet('budgetelle.key.' + target) });
    }
    return res.status(200).json({ pw: await kvGet('budgetelle.key.' + s.email.toLowerCase()) });
  }

  if (req.method === 'POST') {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 5_000) req.destroy(); });
    req.on('end', async () => {
      try {
        const { pw } = JSON.parse(body);
        if (!pw || typeof pw !== 'string' || pw.length < 20 || pw.length > 200) return res.status(400).json({ error: 'Bad key' });
        await kvSet('budgetelle.key.' + s.email.toLowerCase(), pw);
        res.status(200).json({ ok: true });
      } catch { res.status(400).json({ error: 'Bad request' }); }
    });
    return;
  }
  res.status(405).json({ error: 'Method not allowed' });
};
