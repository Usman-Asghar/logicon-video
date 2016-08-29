'use strict';

/**
 * Module dependencies
 */
var articlesPolicy = require('../policies/articles.server.policy'),
  path = require('path'),
  articles = require('../controllers/articles.server.controller'),
  jwtauth = require(path.resolve('./config/jwtauth'));

module.exports = function(app) {
  // Articles collection routes
  app.route('/api/articles').all([articlesPolicy.isAllowed,jwtauth.auth])
    .get(articles.list)
    .post(articles.create);

  // Single article routes
  app.route('/api/articles/:articleId').all(articlesPolicy.isAllowed)
    .get(articles.read)
    .put(articles.update)
    .delete(articles.delete);
};