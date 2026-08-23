// Step 2: exchange the authorization code for tokens, mint our own signed session
const { verify, sign, cookieHeader, parseCookies, SITE, oauthConfigured } = require('../../_lib/session');

module.exports = async (req, res) => {
  try {
    const { code, state } = req.query;
    const cookies = parseCookies(req);
    const verifier = cookies.btauth_pv;

    if (!oauthConfigured() || !code || !state || !verifier) {
      return res.status(302).redirect('/?auth=failed');
    }
    // CSRF check: state we minted must still be valid
    if (!verify(state)) return res.status(302).redirect('/?auth=failed');

    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: `${SITE}/api/auth/google/callback`,
        grant_type: 'authorization_code',
        code_verifier: verifier,
      }),
    });
    const tokens = await tokenRes.json();
    if (!tokens.id_token) return res.status(302).redirect('/?auth=failed');

    // decode id_token payload (already over a TLS round-trip with Google — no need to re-verify sig)
    const payload = JSON.parse(Buffer.from(tokens.id_token.split('.')[1], 'base64url').toString());
    if (!payload.email) return res.status(302).redirect('/?auth=failed');

    // our own session cookie — the browser never sees Google's tokens
    const session = sign({ sub: payload.sub, email: payload.email, name: payload.name || '', exp: Date.now() + 1000 * 60 * 60 * 24 * 14 });
    res.setHeader('Set-Cookie', [
      cookieHeader('bt_session', session, 60 * 60 * 24 * 14),
      `btauth_pv=; Path=/api/auth; HttpOnly; Max-Age=0`,
    ]);
    res.status(302).redirect(`/?auth=google&email=${encodeURIComponent(payload.email)}&name=${encodeURIComponent(payload.name || '')}`);
  } catch {
    res.status(302).redirect('/?auth=failed');
  }
};
