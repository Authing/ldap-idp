!(function(n) {
  'function' == typeof define && define.amd ? define(n) : n();
})(function() {
  'use strict';
  const n = require('ldapjs'),
    e = require('mongodb').MongoClient,
    o = require('./ldapdb.json'),
    s = require('assert'),
    t = [
      'mongodb://',
      o.user + ':' + o.password + '@',
      o.ip,
      ':',
      o.port,
      '/',
      o.dbname,
    ].join('');
  e.connect(t, function(n, e) {
    s.equal(null, n), console.log('Connected successfully to server');
    const t = e.db(o.dbname);
    r(t);
  });
  const r = e => {
    const o = n.createServer(),
      t = function(n) {
        const o = e.collection('users');
        o.find({}).toArray(function(e, o) {
          s.equal(e, null), n(o);
        });
      };
    o.bind('cn=root', function(n, e, o) {
      return console.log(n.dn.rdns), e.end(), o();
    });
    const r = [
      function(e, o, s) {
        return e.connection.ldap.bindDN.equals('cn=root')
          ? s()
          : s(new n.InsufficientAccessRightsError());
      },
      function(n, e, o) {
        t(e => {
          n.users = {};
          for (var s = 0; s < e.length; s++) {
            const o = e[s];
            n.users[o._id] = {
              dn: `cn=${o.username || o.email || o.phone || o.unionid},uid=${
                o._id
              }, ou=users, o=authingId, dc=authing, dc=cn`,
              attributes: {
                cn: o.username || o.email || o.phone || o.unionid,
                uid: o._id,
                gid: o._id,
                username: o.username,
                objectclass: 'authingUser',
              },
            };
          }
          return o();
        });
      },
    ];
    o.search('o=authingId, ou=users, dc=authing, dc=cn', r, function(n, e, o) {
      return (
        Object.keys(n.users).forEach(function(o) {
          n.filter.matches(n.users[o].attributes) && e.send(n.users[o]);
        }),
        e.end(),
        o()
      );
    }),
      o.listen(1389, function() {
        console.log('LDAP server up at: %s', o.url);
      });
  };
});
//# sourceMappingURL=ldap-idp.umd.production.js.map
