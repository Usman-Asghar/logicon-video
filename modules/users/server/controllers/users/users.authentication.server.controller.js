'use strict';

/**
 * Module dependencies.
 */
var path = require('path'),
  db = require(path.resolve('./config/lib/sequelize')),
  errorHandler = require(path.resolve('./modules/core/server/controllers/errors.server.controller')),
  passport = require('passport'),
  jwt = require('jwt-simple'),
  moment = require('moment');
// URLs for which user can't be redirected on signin
var noReturnUrls = [
  '/authentication/signin',
  '/authentication/signup'
];

var emailRE = /^[-a-z0-9~!$%^&*_=+}{\'?]+(\.[-a-z0-9~!$%^&*_=+}{\'?]+)*@([a-z0-9_][-a-z0-9_]*(\.[-a-z0-9_]+)*\.(aero|arpa|biz|com|coop|edu|gov|info|int|mil|museum|name|net|org|pro|travel|mobi|[a-z][a-z])|([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}))(:[0-9]{1,5})?$/i;
var passwordRE = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[$@$!%*#?&])[A-Za-z\d$@$!%*#?&]{8,}$/;

/**
 * Check Email
*/
exports.checkusername = function(req, res) {
  if (req.body.username !== undefined) {
    if(req.body.username === '')
    {
      return res.status(200).send({
        message: 'Empty Parameters',
        error: true
      });
    }
    else
    {
      db.User
        .findOne({
          where: {
            username: req.body.username
          }
        })
        .then(function(user) {
          if (user) {
            return res.status(200).send({
              message: 'Username found',
              error: true
            });
          } else{
            return res.status(200).send({
              message: 'No username found',
              error: false
            });
          }
        })
        .catch(function(err) {
          return res.status(200).send({
            message: errorHandler.getErrorMessage(err),
            error: true
          });
        });
    }
  } else{
    return res.status(400).send({
      message: 'insufficient Parameters',
      error: true
    });
  }
};

/**
 * Check Username
*/
exports.chekemail = function(req, res) {
  if (req.body.email !== undefined) {
    if(req.body.email === '')
    {
      return res.status(200).send({
        message: 'Empty Parameters',
        error: true
      });
    }
    else
    {
      var emailvalidate = emailRE.test(req.body.email);
      if(!emailvalidate){
        return res.status(200).send({
          message: 'Invalid email format',
          error: true
        });
      }
      else{
        db.User
          .findOne({
            where: {
              email: req.body.email
            }
          })
          .then(function(user) {
            if (user) {
              return res.status(200).send({
                message: 'Email found',
                error: true
              });
            } else{
              return res.status(200).send({
                message: 'No email found',
                error: false
              });
            }
          })
          .catch(function(err) {
            return res.status(200).send({
              message: errorHandler.getErrorMessage(err),
              error: true
            });
          });
      }
    }
  } else{
    return res.status(400).send({
      message: 'insufficient Parameters',
      error: true
    });
  }
};

/**
 * Signup
 */
exports.signup = function(req, res) {
  // For security measurement we remove the roles from the req.body object
  if (req.body.email !== undefined && req.body.password !== undefined) {
    if(req.body.email === '' || req.body.password === '')
    {
      return res.status(200).send({
        message: 'Empty Parameters',
        error: true
      });
    }
    else
    {
      var emailValidate = emailRE.test(req.body.email);
      var passwordValidate = passwordRE.test(req.body.password);
      if(!emailValidate){
        return res.status(200).send({
          message: 'Invalid email format',
          error: true
        });
      }
      else if(!passwordValidate){
        return res.status(200).send({
          message: 'Invalid password format',
          error: true
        });
      }
      else{
        delete req.body.roles;

        // Init Variables
        var message = null;

        // Add missing user fields
        var provider = 'local';

        // Save user
        db.User
          .create({
            email: req.body.email,
            username: null,
            password: req.body.password,
            salt: req.body.salt,
            profileImageURL: null,
            provider: provider,
            providerData: null,
            additionalProvidersData: null,
            resetPasswordToken: null,
            resetPasswordExpires: null,
            active: 1,
            verified: 1
          })
          .then(function(user) {
            // Find role
            db.Role
              .findOne({
                where: {
                  name: 'user'
                }
              })
              .then(function(role) {
                // Add role
                user
                  .addRoles(role)
                  .then(function(role) {

                    user.dataValues.roles = ['user'];

                    user.dataValues.password = null;
                    user.dataValues.salt = null;

                    user._previousDataValues.password = null;
                    user._previousDataValues.salt = null;
                    // Login
                    req.login(user, function(err) {
                      if (err) {
                        return res.status(200).send(err);
                      } else {
                        return res.json(user);
                      }
                    });

                    return null;
                  })
                  .catch(function(err) {
                    return res.status(200).send({
                      message: errorHandler.getErrorMessage(err),
                      error: true
                    });
                  });
                return null;
              })
              .catch(function(err) {
                return res.status(200).send({
                  message: errorHandler.getErrorMessage(err),
                  error: true
                });
              });

            return null;
          })
          .catch(function(err) {
            return res.status(200).send({
              message: errorHandler.getErrorMessage(err),
              error: true
            });
          });
      }
    }
  }
  else
  {
    return res.status(400).send({
      message: 'Insufficient Parameters',
      error: true
    });  
  }
};

/**
 * Signin after passport authentication
 */
exports.signin = function(req, res, next) {
  if (req.body.email !== undefined && req.body.password !== undefined) {
    if(req.body.email === '' || req.body.password === '')
    {
      return res.status(200).send({
        message: 'Empty Parameters',
        error: true
      });
    }
    else
    {
      var emailValidate = emailRE.test(req.body.email);
      if(!emailValidate){
        return res.status(200).send({
          message: 'Invalid email format',
          error: true
        });
      }
      else{
        passport.authenticate('local', function(err, user, info) {
          if (err || !user) {
            res.status(200).send(info);
          } else {
            req.login(user, function(err) {
              if (err) {
                res.status(200).send(err);
              } else {
                user
                  .getRoles()
                  .then(function(roles) {
                    var rolesArray = [];
                    var expires = moment().add(7,'days').valueOf();
                    var token = jwt.encode({
                      iss: user.id,
                      exp: expires
                    }, 'TOPSECRET');
                    roles.map(function(dataValues) {
                      rolesArray.push(dataValues.name);
                    });
                    user.dataValues.token = token;
                    user.dataValues.roles = rolesArray;
                    user.dataValues.password = null;
                    user.dataValues.salt = null;
                    return res.json(user);
                  })
                  .catch(function(err) {
                    return res.status(200).send({
                      message: errorHandler.getErrorMessage(err),
                      error: true
                    });
                  });
              }
            });
          }
        })(req, res, next);
      }
    }
  }
  else
  {
    return res.status(400).send({
      message: 'insufficient Parameters',
      error: true
    });
  }
};

/**
 * Signout
 */
exports.signout = function(req, res) {
  req.logout();

  req.session.destroy(function (err) {
    res.redirect('/');
  });
};

/**
 * OAuth provider call
 */
exports.oauthCall = function(strategy, scope) {
  return function(req, res, next) {
    // Set redirection path on session.
    // Do not redirect to a signin or signup page
    if (noReturnUrls.indexOf(req.query.redirect_to) === -1) {
      req.session.redirect_to = req.query.redirect_to;
    }
    // Authenticate
    passport.authenticate(strategy, scope)(req, res, next);
  };
};

/**
 * OAuth callback
 */
exports.oauthCallback = function(strategy) {
  return function(req, res, next) {
    // Pop redirect URL from session
    var sessionRedirectURL = req.session.redirect_to;
    delete req.session.redirect_to;

    passport.authenticate(strategy, function(err, user, redirectURL) {
      if (err) {
        return res.redirect('/authentication/signin?err=' + encodeURIComponent(errorHandler.getErrorMessage(err)));
      }

      if (!user) {
        return res.redirect('/authentication/signin');
      }

      req.login(user, function(err) {
        if (err) {
          return res.redirect('/authentication/signin');
        } else {
          return res.redirect(redirectURL || sessionRedirectURL || '/');
        }
      });

    })(req, res, next);
  };
};

/**
 * Helper function to save or update a OAuth user profile
 */
exports.saveOAuthUserProfile = function(req, providerUserProfile, done) {
  if (!req.user) {
    // Define a search query fields
    var searchMainProviderIdentifierField = 'providerData.' + providerUserProfile.providerIdentifierField;
    var searchAdditionalProviderIdentifierField = 'additionalProvidersData.' + providerUserProfile.provider + '.' + providerUserProfile.providerIdentifierField;

    // Define main provider search query
    var mainProviderSearchQuery = {};
    mainProviderSearchQuery.provider = providerUserProfile.provider;
    mainProviderSearchQuery[searchMainProviderIdentifierField] = providerUserProfile.providerData[providerUserProfile.providerIdentifierField];

    // Define additional provider search query
    var additionalProviderSearchQuery = {};
    additionalProviderSearchQuery[searchAdditionalProviderIdentifierField] = providerUserProfile.providerData[providerUserProfile.providerIdentifierField];

    // Define a search query to find existing user with current provider profile
    var searchQuery = {
      $or: [mainProviderSearchQuery, additionalProviderSearchQuery]
    };

    db.User
      .findOne({
        where: searchQuery
      })
      .then(function(user) {

        if (!user) {
          var possibleUsername = providerUserProfile.username || ((providerUserProfile.email) ? providerUserProfile.email.split('@')[0] : '');

          db.User.findUniqueUsername(possibleUsername, null, function(availableUsername) {

            if (availableUsername) {

              db.User
                .create({
                  firstName: providerUserProfile.firstName,
                  lastName: providerUserProfile.lastName,
                  username: availableUsername,
                  displayName: providerUserProfile.displayName,
                  email: providerUserProfile.email,
                  profileImageURL: providerUserProfile.profileImageURL,
                  provider: providerUserProfile.provider,
                  providerData: providerUserProfile.providerData
                })
                .then(function(user) {

                  db.Role
                    .findOne({
                      where: {
                        name: 'user'
                      }
                    })
                    .then(function(role) {
                      // Add role
                      user
                        .addRoles(role)
                        .then(function(role) {
                          done(null, user);
                          return null;
                        })
                        .catch(function(err) {
                          done(err);
                          return null;
                        });

                      return null;
                    })
                    .catch(function(err) {
                      done(err);
                      return null;
                    });

                  return null;
                })
                .catch(function(err) {
                  done(err);
                  return null;
                });
            }
          });

        } else {
          done(null, user);
          return null;
        }

        return null;
      })
      .catch(function(err) {
        done(err);
        return null;
      });

  } else {
    // User is already logged in, join the provider data to the existing user
    var user = req.user;

    // Check if user exists, is not signed in using this provider, and doesn't have that provider data already configured
    if (user.provider !== providerUserProfile.provider && (!user.additionalProvidersData || !user.additionalProvidersData[providerUserProfile.provider])) {

      // Add the provider data to the additional provider data field
      if (!user.additionalProvidersData) {
        user.additionalProvidersData = {};
      }

      user.additionalProvidersData[providerUserProfile.provider] = providerUserProfile.providerData;

      // And save the user
      user
        .save()
        .then(function() {
          done(null, user, '/settings/accounts');
          return null;
        })
        .catch(function(err) {
          done(err);
          return null;
        });
    } else {
      done(new Error('User is already connected using this provider'), user);
    }
  }
};

/**
 * Remove OAuth provider
 */
exports.removeOAuthProvider = function(req, res, next) {
  var user = req.user;
  var provider = req.query.provider;

  if (!user) {
    return res.status(401).json({
      message: 'User is not authenticated'
    });
  } else if (!provider) {
    res.status(400).send();
  }

  //Delete the additional provider
  if (user.dataValues.additionalProvidersData[provider]) {
    var data = user.dataValues.additionalProvidersData;
    delete data[provider];
    user.additionalProvidersData = data;
  }

  user
    .save()
    .then(function(user) {
      req.login(user, function(err) {
        if (err) {
          return res.status(400).send(err);
        } else {
          return res.json(user);
        }
      });

      return null;
    })
    .catch(function(err) {
      return res.status(400).send({
        message: errorHandler.getErrorMessage(err)
      });
    });
};
