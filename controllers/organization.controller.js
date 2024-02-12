const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const Organization = require('../models/organization.model');

require('dotenv').config();

const jwtSecret = process.env.JWT_SECRET;

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
  const { organizationName, password, email, contactInformation, website, missionStatement } = req.body;

  // Validate input and check for existing organization
  if (!organizationName || !password || !email || !contactInformation || !website || !missionStatement) {
    return res.status(422).json({ error: 'All fields are required.' });
  }

  // Check if the password meets the criteria
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  if (!passwordRegex.test(password)) {
    return res.status(422).json({
      error: 'Password must have 8 or more characters, at least one uppercase letter, one lowercase letter, one digit, and one special character.',
    });
  }

  try {
    const existingOrganization = await Organization.findOne({ $or: [{ organizationName }, { email }] });

    if (existingOrganization) {
      return res.status(422).json({ error: 'Organization name or email is already taken.' });
    }

    const organization = new Organization({
      organizationName,
      password,
      email,
      contactInformation,
      website,
      missionStatement,
    });
    await organization.save();

    // Generate email verification token
    const emailVerificationToken = crypto.randomBytes(20).toString('hex');
    organization.emailVerificationToken = emailVerificationToken;
    await organization.save();

    // Send email verification link
    const verificationLink = `${process.env.APP_BASE_URL}/auth/verify-email/organization/${emailVerificationToken}`;

    const mailOptions = {
      from: 'harmonyplateenvironments@gmail.com',
      to: organization.email,
      subject: 'HarmonyPlate - Verify Your Email',
      html: `Click the following link to verify your email: <a href="${verificationLink}">${verificationLink}</a>`,
    };

    transporter.sendMail(mailOptions, (error) => {
      if (error) {
        console.error('Email verification email failed to send:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      res.json({ message: 'Organization registered successfully. Check your email for verification.' });
    });
  } catch (error) {
    next(error);
  }
};

// Login
exports.login = async (req, res, next) => {
  const { organizationName, password } = req.body;

  if (!organizationName || !password) {
    return res.status(422).json({ error: 'Organization name and password are required.' });
  }

  try {
    const organization = await Organization.findOne({ organizationName });

    if (!organization) {
      return res.status(404).json({ error: 'Organization not found.' });
    }

    if (!organization.isVerified) {
      return res.status(401).json({ error: 'Email not verified. Please check your email for verification instructions.' });
    }

    const isPasswordMatch = await organization.comparePassword(password);

    if (!isPasswordMatch) {
      return res.status(401).json({ error: 'Invalid password.' });
    }

    // If organization name and password are correct, generate a JWT token
    const token = jwt.sign(
      { id: organization._id, organizationName: organization.organizationName, role: 'organization' },
      jwtSecret,
      { expiresIn: '1h' }
    );

    res.json({ token });
  } catch (error) {
    next(error);
  }
};
// forgot password
exports.forgotPassword = async (req, res, next) => {
  const { email } = req.body;

  try {
    const organization = await Organization.findOne({ email });

    if (!organization) {
      return res.status(404).json({ error: 'Organization not found.' });
    }

    // Generate password reset token
    organization.generatePasswordResetToken();
    await organization.save();

    // Send password reset link
    const resetLink = `${process.env.APP_BASE_URL}/auth/reset-password/organization/${organization.passwordResetToken}`;

    const mailOptions = {
      from: 'harmonyplateenvironments@gmail.com',
      to: organization.email,
      subject: 'HarmonyPlate - Reset Your Password',
      html: `Click the following link to reset your password: <a href="${resetLink}">${resetLink}</a>`,
    };

    transporter.sendMail(mailOptions, (error) => {
      if (error) {
        console.error('Password reset email failed to send:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      res.json({ message: 'Password reset instructions sent to your email.' });
    });
  } catch (error) {
    next(error);
  }
};
//Reset Password
exports.resetPassword = async (req, res, next) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  try {
    const organization = await Organization.findOne({
      passwordResetToken: token,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!organization) {
      return res.status(404).json({ error: 'Invalid or expired password reset token.' });
    }

    // Update password
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(newPassword, salt);
    organization.password = hash;
    organization.passwordResetToken = undefined;
    organization.passwordResetExpires = undefined;
    await organization.save();

    res.json({ message: 'Password reset successfully.' });
  } catch (error) {
    next(error);
  }
};

// Verify Email
exports.verifyEmail = async (req, res) => {
  const { token } = req.params;

  try {
    const organization = await Organization.findOne({ emailVerificationToken: token });

    if (!organization) {
      return res.status(404).json({ error: 'Invalid verification token.' });
    }

    // Mark the organization as verified
    organization.isVerified = true;
    organization.emailVerificationToken = undefined;
    await organization.save();

    res.json({ message: 'Email verified successfully. You can now sign in.' });
  } catch (error) {
    console.error('Email verification failed:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};



