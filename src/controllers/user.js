const JWT = require('jsonwebtoken');
const User = require('../models/user');
const Payload = require('../services/JWTBlockchainPayload');

const Secret = process.env.SECRET;

let signToken = (user) => {
  return JWT.sign(
    Payload,
    Secret,
    {
      algorithm: 'HS256',
      noTimestamp: true
    }
  );
};

module.exports = {
  signUp: async (req, res, next) => {
    const { email, password } = req.value.body;

    //Check if another user has same email
    const foundUser = await User.findOne({ 'local.email': email });
    if (foundUser) {
      return res.status(403).json({ error: 'Email is already in use'});
    }

    const newUser = new User({
      method: 'local',
      local: {
        email: email,
        password: password
      }
    });

    await newUser.save();

    // Generate Token
    const token = signToken(newUser);
    res.status(200).json({ token });
  },

  signIn: async (req, res, next) => {
    // Generate token
    const token = signToken(req.user);
    res.status(200).json({ token });
  },

  secret: async (req, res, next) => {
    console.log('I managed to get here!');
    res.json({ secret: 'resource' });
  }
};
