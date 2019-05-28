const n = require('ldapjs'),
  e = require('mongodb').MongoClient,
  o = require('./ldapdb.json'),
  s = require('assert'),
  r = [
    'mongodb://',
    o.user + ':' + o.password + '@',
    o.ip,
    ':',
    o.port,
    '/',
    o.dbname,
  ].join('');
e.connect(r, function(n, e) {
  s.equal(null, n), console.log('Connected successfully to server');
  const r = e.db(o.dbname);
  u(r);
});
const u = e => {
  const o = n.createServer(),
    r = function(n) {
      const o = e.collection('users');
      o.find({}).toArray(function(e, o) {
        s.equal(e, null), n(o);
      });
    };
  o.bind('cn=root', function(n, e, o) {
    return console.log(n.dn.rdns), e.end(), o();
  });
  const u = [
    function(e, o, s) {
      return e.connection.ldap.bindDN.equals('cn=root')
        ? s()
        : s(new n.InsufficientAccessRightsError());
    },
    function(n, e, o) {
      r(e => {
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
  o.search('o=authingId, ou=users, dc=authing, dc=cn', u, function(n, e, o) {
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
//# sourceMappingURL=ldap-idp.es.production.js.map
