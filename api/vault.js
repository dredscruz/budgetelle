// Cloud vault: store/retrieve the encrypted vault blob.
// GET ?email=... -> { doc } for that account, but ONLY when the requester holds
//                   a valid household code redemption for it; otherwise only
//                   their own doc is returned. POST saves the requester's own.
const { verify, parseCookies } = require('./_lib/session');
const { kvGet, kvSet } = require('./_lib/store');

module.exports = async (req, res) => {
  const s = verify(parseCookies(req).bt_session);
  if (!s || !s.email) return res.status(401).json({ error: 'Not signed in' });
  const mine = 'budgetelle.vault.' + s.email.toLowerCase();

  if (req.method === 'GET') {
    const url = new URL(req.url, 'http://x');
    let target = url.searchParams.get('email');
    if (target) {
      target = target.toLowerCase();
      // cross-account read is allowed only with a recently redeemed code
      const redemption = await kvGet('budgetelle.redeemed.' + s.email.toLowerCase());
      if (redemption !== target) return res.status(200).json({ doc: null });
      return res.status(200).json({ doc: await kvGet('budgetelle.vault.' + target) });
    }
    return res.status(200).json({ doc: await kvGet(mine) });
  }

  if (req.method === 'POST') {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 3_000_000) req.destroy(); });
    req.on('end', async () => {
      try {
        const { doc } = JSON.parse(body);
        if (!doc || typeof doc !== 'string' || doc.length > 2_500_000) return res.status(400).json({ error: 'Bad doc' });
        await kvSet(mine, doc);
        res.status(200).json({ ok: true });
      } catch { res.status(400).json({ error: 'Bad request' }); }
    });
    return;
  }
  res.status(405).json({ error: 'Method not allowed' });
};
