const n = require('ldapjs'),
  e = require('fs'),
  s = require('mongodb').MongoClient,
  r = require('./ldapdb.json'),
  o = require('assert'),
  t = [
    'mongodb://',
    r.user + ':' + r.password + '@',
    r.ip,
    ':',
    r.port,
    '/',
    r.dbname,
  ].join('');
s.connect(t, function(n, e) {
  o.equal(null, n), console.log('Connected successfully to server');
  const s = e.db(r.dbname);
  c();
  !(function(n, e) {
    const s = n.collection('users');
    s.find({}).toArray(function(n, s) {
      o.equal(n, null), e(s);
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
  const r = [
    function(e, s, r) {
      return e.connection.ldap.bindDN.equals('cn=root')
        ? r()
        : r(new n.InsufficientAccessRightsError());
    },
    function(s, r, o) {
      e.readFile('/etc/passwd', 'utf8', function(e, r) {
        if (e) return o(new n.OperationsError(e.message));
        s.users = {};
        for (var t = r.split('\n'), c = 0; c < t.length; c++)
          if (t[c] && !/^#/.test(t[c])) {
            var u = t[c].split(':');
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
        return o();
      });
    },
  ];
  s.search('o=authingId, ou=users, dc=authing, dc=cn', r, function(n, e, s) {
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
//# sourceMappingURL=ldap-idp.es.production.js.map
