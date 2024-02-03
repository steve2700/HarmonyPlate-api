// middlewares/authenticate.js
const passport = require('passport');

const requireAuth = passport.authenticate('jwt', { session: false });
const requireAdmin = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    return next();
  }
  return res.status(403).json({ error: 'Access Denied. Admin privileges required.' });
};

module.exports = { requireAuth, requireAdmin };

