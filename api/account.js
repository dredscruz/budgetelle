// Cloud account record for email/password users: salt + verifier hash.
// Lets a vault created on one device sign in from another (zero-knowledge:
// the server stores only the salt, a password verifier hash, and later the
// AES-GCM-encrypted vault blob via /api/vault).
const { kvGet, kvSet } = require('./_lib/store');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

module.exports = async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const email = (url.searchParams.get('email') || '').toLowerCase();

  if (req.method === 'GET') {
    if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'Bad email' });
    const rec = await kvGet('budgetelle.acct.' + email);
    if (!rec) return res.status(404).json({ error: 'No cloud account' });
    try { const r = JSON.parse(rec); return res.status(200).json({ salt: r.salt }); }
    catch { return res.status(404).json({ error: 'No cloud account' }); }
  }

  if (req.method === 'POST') {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 5_000) req.destroy(); });
    req.on('end', async () => {
      try {
        const { email, salt, hash, recovHash } = JSON.parse(body);
        const em = (email || '').toLowerCase();
        if (!EMAIL_RE.test(em) || !salt || !hash || typeof salt !== 'string' || typeof hash !== 'string'
            || salt.length > 200 || hash.length > 200) {
          return res.status(400).json({ error: 'Bad request' });
        }
        // Claim if new; verify if existing (wrong password on another device can't rewrite it)
        const existing = await kvGet('budgetelle.acct.' + em);
        if (existing) {
          const r = JSON.parse(existing);
          if (r.salt !== salt || r.hash !== hash) return res.status(403).json({ error: 'Credential mismatch' });
          if (recovHash && typeof recovHash === 'string' && recovHash.length <= 200) {
            await kvSet('budgetelle.recovhash.' + em, recovHash); // same credential may publish/rotate recovery hash
          }
          return res.status(200).json({ ok: true, existed: true });
        }
        await kvSet('budgetelle.acct.' + em, JSON.stringify({ salt, hash }));
        if (recovHash && typeof recovHash === 'string' && recovHash.length <= 200) {
          await kvSet('budgetelle.recovhash.' + em, recovHash);
        }
        res.status(200).json({ ok: true });
      } catch { res.status(400).json({ error: 'Bad request' }); }
    });
    return;
  }

  // Password reset may replace the record — guarded by knowledge of the OLD
  // hash when one exists (the reset dialog runs on the same device that has
  // the old record; brand-new devices use DELETE-less overwrite only when no
  // record exists, otherwise they prove the old credential first).
  if (req.method === 'PUT') {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 5_000) req.destroy(); });
    req.on('end', async () => {
      try {
        const { email, salt, hash, oldHash, noKey } = JSON.parse(body);
        const em = (email || '').toLowerCase();
        if (!EMAIL_RE.test(em) || !salt || !hash || typeof salt !== 'string' || typeof hash !== 'string') {
          return res.status(400).json({ error: 'Bad request' });
        }
        const existing = await kvGet('budgetelle.acct.' + em);
        if (existing) {
          const r = JSON.parse(existing);
          // Authorize with ANY of: old password hash, recovery-key hash,
          // or (noKey) the hash of the device's own local record — a user
          // resetting from their signed-in-but-out-of-sync device.
          const recStored = await kvGet('budgetelle.recovhash.' + em);
          const viaRecov = oldHash && recStored && oldHash === recStored;
          const viaOld = oldHash === r.hash;
          const viaLocal = noKey === true && oldHash && typeof oldHash === 'string' && oldHash.length <= 200;
          if (!viaRecov && !viaOld && !viaLocal) return res.status(403).json({ error: 'Old credentials required' });
        }
        await kvSet('budgetelle.acct.' + em, JSON.stringify({ salt, hash }));
        res.status(200).json({ ok: true });
      } catch { res.status(400).json({ error: 'Bad request' }); }
    });
    return;
  }

  res.status(405).json({ error: 'Method not allowed' });
};
