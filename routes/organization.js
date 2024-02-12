// Organization routes
const express = require('express');
const organizationController = require('../controllers/organization.controller');
const router = express.Router();

router.post('/signup', organizationController.signup);
router.post('/login', organizationController.login);
router.get('/verify-email/:token', organizationController.verifyEmail);
router.post('/forgot-password', organizationController.forgotPassword);
router.post('/reset-password/:token', organizationController.resetPassword);

module.exports = router;

