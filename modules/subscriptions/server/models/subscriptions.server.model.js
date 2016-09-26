'use strict';

/**
 * Subscription Schema
 */
module.exports = function(sequelize, DataTypes) {

  var Subscription = sequelize.define('Subscription', {
    email: {
      allowNull: false,
      type: DataTypes.STRING,
      validate: {
        isEmail: true,
        notEmpty: true
      }
    },
    interest: {
      allowNull: true,
      type: DataTypes.STRING
    }
  });

  return Subscription;
};
