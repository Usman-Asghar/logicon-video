// @file jwtauth.js
'use strict';
var path = require('path'),
  db = require(path.resolve('./config/lib/sequelize')),
  jwt = require('jwt-simple');

exports.auth = function(req, res, next) {
  var token = (req.body && req.body.access_token) || (req.query && req.query.access_token) || req.headers['x-access-token'];
  if (token) {
    try {
      var decoded = jwt.decode(token, 'TOPSECRET');
      if (decoded.exp <= Date.now()) {
        return res.status(400).json({
          error: true,
          message: 'Access token has expired'
        });
      }
      else{
        if(req.user.dataValues.id === decoded.iss)
        {
          return next();
        }
        else
        {
          return res.status(400).json({
            error: true,
            message: 'Access token is Invalid'
          });
        }
      }
    } catch (err) {
      return res.status(400).json({
        error: true,
        message: err
      });
    }
  } else {
    return res.status(400).json({
      error: true,
      message: 'Access token not found'
    });
  }
};