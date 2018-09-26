require('dotenv').config();
const passport = require('passport');
const JWTStrategy = require('passport-jwt').Strategy;
const { ExtractJwt } = require('passport-jwt');
const LocalStrategy = require('passport-local').Strategy;
const User = require('./models/user');

// JSON Web Token Strategy
passport.use(new JWTStrategy({
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: process.env.SECRET
}, async (payload, done) => {
  try {
    const user = await User.findById(payload.sub);

    if (!user) {
      return done(null, false);
    }

    done(null, user);
  } catch(err) {
    done(err, false)
  }
}));

passport.use(new LocalStrategy({
  usernameField: 'email'
}, async (email, password, done) => {
  try {
    const user = await User.findOne({ 'local.email': email });
    if (!user) {
      return done(null, false);
    }

    const isMatch = await user.isValidPassword(password);
    if (!isMatch) {
      return done(null, user);
    }

    done(null, user);
  } catch(err) {
    done(err, false);
  }
}));
