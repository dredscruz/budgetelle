// Returns the current Google session (if any)
const { verify, parseCookies } = require('../_lib/session');
module.exports = (req, res) => {
  const s = verify(parseCookies(req).bt_session);
  if (!s) return res.status(200).json({ authenticated: false });
  res.status(200).json({ authenticated: true, email: s.email, name: s.name });
};
