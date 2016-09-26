'use strict';

/**
 * Module dependencies
 */
var subscriptionsPolicy = require('../policies/subscriptions.server.policy'),
  path = require('path'),
  subscriptions = require('../controllers/subscriptions.server.controller'),
  jwtauth = require(path.resolve('./config/jwtauth'));

module.exports = function(app) {
  // Articles collection routes
  app.route('/api/subscriptions').all([subscriptionsPolicy.isAllowed,jwtauth.auth])
    .get(subscriptions.list)
    .post(subscriptions.create);

  // Single article routes
  app.route('/api/subscriptions/:articleId').all(subscriptionsPolicy.isAllowed)
    .get(subscriptions.read)
    .put(subscriptions.update)
    .delete(subscriptions.delete);
};