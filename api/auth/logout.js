// Signs out of the Google session
const { cookieHeader } = require('../_lib/session');
module.exports = (req, res) => {
  res.setHeader('Set-Cookie', cookieHeader('bt_session', '', 0));
  res.status(200).json({ ok: true });
};
