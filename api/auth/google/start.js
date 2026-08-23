// Step 1: redirect to Google with PKCE + state
const crypto = require('crypto');
const { sign, cookieHeader, SITE, oauthConfigured } = require('../../_lib/session');

module.exports = (req, res) => {
  if (!oauthConfigured()) {
    return res.status(302).redirect('/?auth=unconfigured');
  }  
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const state = crypto.randomBytes(12).toString('base64url');

  const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  url.searchParams.set('client_id', process.env.GOOGLE_CLIENT_ID);
  url.searchParams.set('redirect_uri', `${SITE}/api/auth/google/callback`);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'openid email profile');
  url.searchParams.set('state', sign({ state, exp: Date.now() + 1000 * 600 }));
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('prompt', 'select_account');

  res.setHeader('Set-Cookie', cookieHeader('btauth_pv', verifier, 600));
  res.status(302).redirect(url.toString());
};
