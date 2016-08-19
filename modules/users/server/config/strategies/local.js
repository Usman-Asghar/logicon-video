'use strict';

/**
 * Module dependencies.
 */
var path = require('path'),
  db = require(path.resolve('./config/lib/sequelize')),
  passport = require('passport'),
  LocalStrategy = require('passport-local').Strategy;

module.exports = function() {
  // Use local strategy
  passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
  },
  function(email, password, done) {
    db.User.findOne({
      where: {
        email: email,
        verified: 1,
        active: 1
      }
    })
    .then(function(user) {
      if (!user || !user.authenticate(user, password)) {
        return done(null, false, {
          message: 'Invalid email or password',
          error: true
        });
      }

      done(null, user);

      return null;
    })
    .catch(function(err) {
      done(err);
    });
  }));
};
