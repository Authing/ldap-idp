const n = require('ldapjs'),
  e = require('mongodb').MongoClient,
  o = require('mongodb').ObjectId,
  t = require('./ldapdb.json'),
  s = require('assert'),
  i = [
    'mongodb://',
    t.user + ':' + t.password + '@',
    t.ip,
    ':',
    t.port,
    '/',
    t.dbname,
  ].join('');
e.connect(i, function(n, e) {
  s.equal(null, n), console.log('Connected successfully to server');
  const o = e.db(t.dbname);
  r(o);
});
const r = e => {
  const t = n.createServer();
  !(function(n) {
    const o = e.collection('userclients');
    o.find({ isDeleted: !1 }).toArray(function(e, o) {
      s.equal(e, null), n(o);
    });
  })(i => {
    const r = (n, t, i) => {
      let r = '';
      const u = n.dn.rdns;
      for (let n = 0; n < u.length; n++) {
        const e = u[n];
        for (let n in e.attrs) 'o' === n && (r = e.attrs.o.value);
      }
      !(function(n, o) {
        const t = e.collection('users');
        (o.isDeleted = !1),
          t.find(o).toArray(function(e, o) {
            s.equal(e, null), n(o);
          });
      })(
        e => {
          n.users = {};
          for (var o = 0; o < e.length; o++) {
            const t = e[o];
            n.users[t._id] = {
              dn: `cn=${t.username || t.email || t.phone || t.unionid},uid=${
                t._id
              }, ou=users, o=${r}, dc=authing, dc=cn`,
              attributes: {
                cn: t.username || t.email || t.phone || t.unionid,
                uid: t._id,
                gid: t._id,
                unionid: t.unionid,
                email: t.email,
                phone: t.phone,
                nickname: t.nickname,
                username: t.username,
                photo: t.photo,
                emailVerified: t.emailVerified,
                oauth: t.oauth,
                token: t.token,
                registerInClient: t.registerInClient,
                loginsCount: t.loginsCount,
                lastIP: t.lastIP,
                company: t.company,
                objectclass: 'authingUser',
              },
            };
          }
          return i();
        },
        { registerInClient: o(r) }
      );
    };
    for (let e = 0; e < i.length; e++) {
      const o = i[e],
        s = `o=${o._id}, ou=users, dc=authing, dc=cn`;
      let u = `ou=users,o=${o._id},dc=authing,dc=cn`;
      t.bind(u, function(n, e, o) {
        return e.end(), o();
      });
      const c = (e, o, t) =>
          e.connection.ldap.bindDN.equals(u)
            ? t()
            : t(new n.InsufficientAccessRightsError()),
        l = [c, r];
      t.search(s, l, function(n, e, o) {
        return (
          Object.keys(n.users).forEach(function(o) {
            n.filter.matches(n.users[o].attributes) && e.send(n.users[o]);
          }),
          e.end(),
          o()
        );
      });
    }
    t.listen(1389, function() {
      console.log('LDAP server up at: %s', t.url);
    });
  });
};
//# sourceMappingURL=ldap-idp.es.production.js.map
