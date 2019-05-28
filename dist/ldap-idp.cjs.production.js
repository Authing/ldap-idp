'use strict';
const n = require('ldapjs'),
  e = require('mongodb').MongoClient,
  s = require('./ldapdb.json'),
  o = require('assert'),
  r = [
    'mongodb://',
    s.user + ':' + s.password + '@',
    s.ip,
    ':',
    s.port,
    '/',
    s.dbname,
  ].join('');
e.connect(r, function(n, e) {
  o.equal(null, n), console.log('Connected successfully to server');
  const r = e.db(s.dbname);
  t(r);
});
const t = e => {
  const s = n.createServer(),
    r = function(n) {
      const s = e.collection('users');
      s.find({}).toArray(function(e, s) {
        o.equal(e, null), n(s);
      });
    };
  s.bind('cn=root', function(n, e, s) {
    return console.log(n.dn.rdns), e.end(), s();
  });
  const t = [
    function(e, s, o) {
      return e.connection.ldap.bindDN.equals('cn=root')
        ? o()
        : o(new n.InsufficientAccessRightsError());
    },
    function(n, e, s) {
      r(e => {
        n.users = {};
        for (var o = 0; o < e.length; o++) {
          const s = e[o];
          n.users[s._id] = {
            dn: `cn=${s.username || s.email || s.phone || s.unionid},uid=${
              s._id
            }, ou=users, o=authingId, dc=authing, dc=cn`,
            attributes: {
              cn: s.username || s.email || s.phone || s.unionid,
              uid: s._id,
              gid: s._id,
              username: s.username,
              objectclass: 'authingUser',
            },
          };
        }
        return s();
      });
    },
  ];
  s.search('o=authingId, ou=users, dc=authing, dc=cn', t, function(n, e, s) {
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
//# sourceMappingURL=ldap-idp.cjs.production.js.map
