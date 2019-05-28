!(function(n) {
  'function' == typeof define && define.amd ? define(n) : n();
})(function() {
  'use strict';
  const n = require('ldapjs'),
    e = require('mongodb').MongoClient,
    t = require('mongodb').ObjectId,
    o = require('./ldapdb.json'),
    i = require('assert'),
    s = [
      'mongodb://',
      o.user + ':' + o.password + '@',
      o.ip,
      ':',
      o.port,
      '/',
      o.dbname,
    ].join('');
  e.connect(s, function(n, e) {
    i.equal(null, n), console.log('Connected successfully to server');
    const t = e.db(o.dbname);
    r(t);
  });
  const r = e => {
    const o = n.createServer();
    !(function(n) {
      const t = e.collection('userclients');
      t.find({ isDeleted: !1 }).toArray(function(e, t) {
        i.equal(e, null), n(t);
      });
    })(s => {
      const r = (n, o, s) => {
        let r = '';
        const u = n.dn.rdns;
        for (let n = 0; n < u.length; n++) {
          const e = u[n];
          for (let n in e.attrs) 'o' === n && (r = e.attrs.o.value);
        }
        !(function(n, t) {
          const o = e.collection('users');
          (t.isDeleted = !1),
            o.find(t).toArray(function(e, t) {
              i.equal(e, null), n(t);
            });
        })(
          e => {
            n.users = {};
            for (var t = 0; t < e.length; t++) {
              const o = e[t];
              n.users[o._id] = {
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
            return s();
          },
          { registerInClient: t(r) }
        );
      };
      for (let e = 0; e < s.length; e++) {
        const t = s[e],
          i = `o=${t._id}, ou=users, dc=authing, dc=cn`;
        let u = `ou=users,o=${t._id},dc=authing,dc=cn`;
        o.bind(u, function(n, e, t) {
          return e.end(), t();
        });
        const c = (e, t, o) =>
            e.connection.ldap.bindDN.equals(u)
              ? o()
              : o(new n.InsufficientAccessRightsError()),
          l = [c, r];
        o.search(i, l, function(n, e, t) {
          return (
            Object.keys(n.users).forEach(function(t) {
              n.filter.matches(n.users[t].attributes) && e.send(n.users[t]);
            }),
            e.end(),
            t()
          );
        });
      }
      o.listen(1389, function() {
        console.log('LDAP server up at: %s', o.url);
      });
    });
  };
});
//# sourceMappingURL=ldap-idp.umd.production.js.map
