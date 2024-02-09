// routes/auth.js
const express = require('express');
const authController = require('../controllers/auth.controller');
const router = express.Router();

router.post('/signup', authController.signup);
router.get('/verify-email/:token', authController.verifyEmail);
router.post('/login', authController.login);

module.exports = router;

