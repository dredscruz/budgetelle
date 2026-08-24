// Replicate forgot-password (no recovery key) then login, exactly as the app does.
const { webcrypto } = require('crypto');
const crypto = webcrypto;
const enc = new TextEncoder();
const BASE = 'https://budgetelle.vercel.app';
(async () => {
  const EM = 'fplive' + Date.now() + '@example.com', PW = 'firstpass1';
  const sha = async s => { const d = await crypto.subtle.digest('SHA-256', enc.encode(s)); return [...new Uint8Array(d)].map(x => x.toString(16).padStart(2, '0')).join(''); };
  // 1. sign up
  const saltB64 = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  const hash = await sha(EM + ':' + PW + ':' + saltB64);
  await fetch(BASE + '/api/account', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: EM, salt: saltB64, hash }) });
  await fetch(BASE + '/api/vault', { method: 'POST', headers: { 'Content-Type': 'application/json', 'bt-email': EM, 'bt-salt': saltB64, 'bt-hash': hash }, body: JSON.stringify({ doc: JSON.stringify({ iv: 'AA', ct: 'BB' }) }) });
  console.log('signed up + saved blob');
  // 2. doReset WITHOUT recovery key -> cloudResetAccount(em) which does PUT with oldHash?
  //    Check the client code path: cloudResetAccount sends {email,salt,hash} — NO oldHash!
  const nsaltB64 = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  const nhash = await sha(EM + ':newpass2:' + nsaltB64);
  // app sends oldHash from the device's local record + noKey flag
  const r2 = await fetch(BASE + '/api/account', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: EM, salt: nsaltB64, hash: nhash, oldHash: hash, noKey: true }) });
  console.log('PUT reset as app sends it:', r2.status, await r2.text());
  if (r2.status !== 200) process.exit(1);
  // 3. clear stale blob with new creds
  const r3 = await fetch(BASE + '/api/vault', { method: 'POST', headers: { 'Content-Type': 'application/json', 'bt-email': EM, 'bt-salt': nsaltB64, 'bt-hash': nhash }, body: JSON.stringify({ doc: '' }) });
  console.log('clear:', await r3.json());
  // 4. sign in with NEW password via cloud path
  const r4 = await fetch(BASE + '/api/account?email=' + encodeURIComponent(EM));
  const { salt: csalt } = await r4.json();
  const chash = await sha(EM + ':newpass2:' + csalt);
  const r5 = await fetch(BASE + '/api/vault', { headers: { 'bt-email': EM, 'bt-salt': csalt, 'bt-hash': chash } });
  console.log('login-after-reset:', r5.status, r5.status === 200 ? 'PASS' : 'FAIL');
})();
