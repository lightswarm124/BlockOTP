const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const Schema = mongoose.Schema;

const userSchema = new Schema({
  method: {
    type: String,
    enum: ['local'],
    required: true
  },
  local: {
    email: {
      type: String,
      lowercase: true
    },
    password: {
      type: String
    }
  }
});

userSchema.pre('save', async function(next) {
  try {
    console.log('entered');
    if(this.method !== 'local') {
      next();
    }

    // Generate Salt
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(this.local.password, salt);
    // Reassign hashed password over plain text
    this.local.password = passwordHash;
    next();
  } catch(error) {
    next(error);
  }
});

userSchema.methods.isValidPassword = async function(newPassword) {
  try {
    return await bcrypt.compare(newPassword, this.local.password);
  } catch(error) {
    throw new Error(error);
  }
};

const User = mongoose.model('user', userSchema);

module.exports = User;
