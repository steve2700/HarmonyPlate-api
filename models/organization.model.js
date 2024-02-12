const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const organizationSchema = new mongoose.Schema({
  organizationName: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  isVerified: { type: Boolean, default: false },
  emailVerificationToken: String,
  contactInformation: { type: String, required: true },
  website: { type: String, required: true },
  missionStatement: { type: String, required: true },
  passwordResetToken: String,
  passwordResetExpires: Date,
});

organizationSchema.pre('save', async function (next) {
  const organization = this;
  if (!organization.isModified('password')) return next();

  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(organization.password, salt);
  organization.password = hash;
  next();
});

organizationSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

organizationSchema.methods.generatePasswordResetToken = function () {
  this.passwordResetToken = crypto.randomBytes(20).toString('hex');
  this.passwordResetExpires = Date.now() + 3600000; // Token valid for 1 hour
};

const Organization = mongoose.model('Organization', organizationSchema);

module.exports = Organization;

