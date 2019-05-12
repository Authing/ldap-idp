
         'use strict'

      if (process.env.NODE_ENV === 'production') {
        module.exports = require('./ldap-idp.cjs.production.js')
      } else {
        module.exports = require('./ldap-idp.cjs.development.js')
      }