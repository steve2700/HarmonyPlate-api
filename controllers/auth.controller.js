// controllers/auth.controller.js
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const User = require('../models/User');

require('dotenv').config();

const jwtSecret = process.env.JWT_SECRET;

// Nodemailer Configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USERNAME,
    pass: process.env.EMAIL_PASSWORD,
    pass: process.env.EMAIL_APP_PASSWORD,
  },
});


// Signup
exports.signup = async (req, res, next) => {
  const { username, password, email } = req.body;

  // Strengthened password criteria
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

  if (!username || !password || !email) {
    return res.status(422).json({ error: 'Username, password, and email are required.' });
  }

  // Check if the password meets the criteria
  if (!passwordRegex.test(password)) {
    return res.status(422).json({
      error: 'Password must have 8 or more characters, at least one uppercase letter, one lowercase letter, one digit, and one special character.',
    });
  }

  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });

    if (existingUser) {
      return res.status(422).json({ error: 'Username or email is already taken.' });
    }

    const user = new User({ username, password, email });
    await user.save();

    // Generate email verification token
    const emailVerificationToken = crypto.randomBytes(20).toString('hex');
    user.emailVerificationToken = emailVerificationToken;
    await user.save();

    // Send email verification link
    const verificationLink = `${process.env.APP_BASE_URL}/auth/verify-email/${emailVerificationToken}`;

    const mailOptions = {
      from: 'harmonyplateenvironments@gmail.com',
      to: user.email,
      subject: 'HarmonyPlate - Verify Your Email',
      html: `Click the following link to verify your email: <a href="${verificationLink}">${verificationLink}</a>`,
    };

    transporter.sendMail(mailOptions, (error) => {
      if (error) {
        console.error('Email verification email failed to send:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      res.json({ message: 'User registered successfully. Check your email for verification.' });
    });
  } catch (error) {
    next(error);
  }
};

// Verify Email
exports.verifyEmail = async (req, res) => {
  const { token } = req.params;

  try {
    const user = await User.findOne({ emailVerificationToken: token });

    if (!user) {
      return res.status(404).json({ error: 'Invalid verification token.' });
    }

    // Mark the user as verified
    user.isVerified = true;
    user.emailVerificationToken = undefined;
    await user.save();

    res.json({ message: 'Email verified successfully. You can now sign in.' });
  } catch (error) {
    console.error('Email verification failed:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

// Login
exports.login = async (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(422).json({ error: 'Username and password are required.' });
  }

  try {
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    if (!user.isVerified) {
      return res.status(401).json({ error: 'Email not verified. Please check your email for verification instructions.' });
    }

    const isPasswordMatch = await user.comparePassword(password);

    if (!isPasswordMatch) {
      return res.status(401).json({ error: 'Invalid password.' });
    }

    // If username and password are correct, generate a JWT token
    const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, jwtSecret, { expiresIn: '1h' });

    res.json({ token });
  } catch (error) {
    next(error);
  }
};

