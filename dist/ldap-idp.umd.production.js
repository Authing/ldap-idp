!(function(n) {
  'function' == typeof define && define.amd ? define(n) : n();
})(function() {
  'use strict';
  const n = require('ldapjs'),
    e = require('fs'),
    s = require('mongodb').MongoClient,
    o = require('./ldapdb.json'),
    t = require('assert'),
    r = [
      'mongodb://',
      o.user + ':' + o.password + '@',
      o.ip,
      ':',
      o.port,
      '/',
      o.dbname,
    ].join('');
  s.connect(r, function(n, e) {
    t.equal(null, n), console.log('Connected successfully to server');
    const s = e.db(o.dbname);
    c();
    !(function(n, e) {
      const s = n.collection('users');
      s.find({}).toArray(function(n, s) {
        t.equal(n, null), e(s);
      });
    })(s, n => {
      console.log(n);
    }),
      e.close();
  });
  const c = () => {
    const s = n.createServer();
    s.bind('cn=root', function(n, e, s) {
      return console.log(n.dn.rdns), e.end(), s();
    });
    const o = [
      function(e, s, o) {
        return e.connection.ldap.bindDN.equals('cn=root')
          ? o()
          : o(new n.InsufficientAccessRightsError());
      },
      function(s, o, t) {
        e.readFile('/etc/passwd', 'utf8', function(e, o) {
          if (e) return t(new n.OperationsError(e.message));
          s.users = {};
          for (var r = o.split('\n'), c = 0; c < r.length; c++)
            if (r[c] && !/^#/.test(r[c])) {
              var u = r[c].split(':');
              u &&
                u.length &&
                (s.users[u[0]] = {
                  dn: `cn=${u[0]},uid=${
                    u[2]
                  }, ou=users, o=authingId, dc=authing, dc=cn`,
                  attributes: {
                    cn: u[0],
                    uid: u[2],
                    gid: u[3],
                    description: u[4],
                    homedirectory: u[5],
                    shell: u[6] || '',
                    objectclass: 'unixUser',
                  },
                });
            }
          return t();
        });
      },
    ];
    s.search('o=authingId, ou=users, dc=authing, dc=cn', o, function(n, e, s) {
      return (
        Object.keys(n.users).forEach(function(s) {
          n.filter.matches(n.users[s].attributes) && e.send(n.users[s]);
        }),
        e.end(),
        s()
      );
    }),
      s.listen(1389, function() {
        console.log('LDAP server up at: %s', s.url);
      });
  };
});
//# sourceMappingURL=ldap-idp.umd.production.js.map
