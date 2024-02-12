// Organization routes
const express = require('express');
const organization = require('../controllers/organization.controller');
const router = express.Router();


router.post('/signup/organization', organizationController.signup);
router.get('/verify-email/organization/:token', organizationController.verifyEmail);
router.post('/forgot-password/organization', organizationController.forgotPassword);
router.post('/reset-password/organization/:token', organizationController.resetPassword);
module.exports = router;
