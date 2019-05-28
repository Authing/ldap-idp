'use strict';
const e = require('ldapjs'),
  n = require('mongodb').MongoClient,
  t = require('mongodb').ObjectId,
  o = require('./ldapdb.json'),
  s = require('assert'),
  i = [
    'mongodb://',
    o.user + ':' + o.password + '@',
    o.ip,
    ':',
    o.port,
    '/',
    o.dbname,
  ].join('');
n.connect(i, function(e, n) {
  s.equal(null, e), console.log('Connected successfully to server');
  const t = n.db(o.dbname);
  r(t);
});
const r = n => {
  const o = e.createServer();
  !(function(e) {
    const t = n.collection('userclients');
    t.find({ isDeleted: !1 }).toArray(function(n, t) {
      s.equal(n, null), e(t);
    });
  })(i => {
    const r = (e, o, i) => {
      let r = '';
      const u = e.dn.rdns;
      for (let e = 0; e < u.length; e++) {
        const n = u[e];
        for (let e in n.attrs) 'o' === e && (r = n.attrs.o.value);
      }
      !(function(e, t) {
        const o = n.collection('users');
        (t.isDeleted = !1),
          o.find(t).toArray(function(n, t) {
            s.equal(n, null), e(t);
          });
      })(
        n => {
          e.users = {};
          for (var t = 0; t < n.length; t++) {
            const o = n[t];
            e.users[o._id] = {
              dn: `cn=${o.username || o.email || o.phone || o.unionid},uid=${
                o._id
              }, ou=users, o=${r}, dc=authing, dc=cn`,
              attributes: {
                cn: o.username || o.email || o.phone || o.unionid,
                uid: o._id,
                gid: o._id,
                unionid: o.unionid,
                email: o.email,
                phone: o.phone,
                nickname: o.nickname,
                username: o.username,
                photo: o.photo,
                emailVerified: o.emailVerified,
                oauth: o.oauth,
                token: o.token,
                registerInClient: o.registerInClient,
                loginsCount: o.loginsCount,
                lastIP: o.lastIP,
                company: o.company,
                objectclass: 'authingUser',
              },
            };
          }
          return i();
        },
        { registerInClient: t(r) }
      );
    };
    for (let n = 0; n < i.length; n++) {
      const t = i[n],
        s = `o=${t._id}, ou=users, dc=authing, dc=cn`;
      let u = `ou=users,o=${t._id},dc=authing,dc=cn`;
      o.bind(u, function(e, n, t) {
        return n.end(), t();
      });
      const c = (n, t, o) =>
          n.connection.ldap.bindDN.equals(u)
            ? o()
            : o(new e.InsufficientAccessRightsError()),
        l = [c, r];
      o.search(s, l, function(e, n, t) {
        return (
          Object.keys(e.users).forEach(function(t) {
            e.filter.matches(e.users[t].attributes) && n.send(e.users[t]);
          }),
          n.end(),
          t()
        );
      });
    }
    o.listen(1389, function() {
      console.log('LDAP server up at: %s', o.url);
    });
  });
};
//# sourceMappingURL=ldap-idp.cjs.production.js.map
