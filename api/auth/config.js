// Tells the front-end whether Google sign-in is configured
const { oauthConfigured } = require('./_lib/session');
module.exports = (req, res) => {
  res.status(200).json({ enabled: oauthConfigured() });
};
