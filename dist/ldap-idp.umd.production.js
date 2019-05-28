!(function(n) {
  'function' == typeof define && define.amd ? define(n) : n();
})(function() {
  'use strict';
  const n = require('ldapjs'),
    e = require('mongodb').MongoClient,
    t = require('mongodb').ObjectId,
    o = require('./ldapdb.json'),
    r = require('assert'),
    i = [
      'mongodb://',
      o.user + ':' + o.password + '@',
      o.ip,
      ':',
      o.port,
      '/',
      o.dbname,
    ].join('');
  e.connect(i, function(n, e) {
    r.equal(null, n), console.log('Connected successfully to server');
    const t = e.db(o.dbname);
    s(t);
  });
  const s = e => {
    const o = n.createServer(),
      i = function(n) {
        return new Promise((t, o) => {
          const r = e.collection('users');
          (n.isDeleted = !1),
            r.find(n).toArray(function(n, e) {
              n && o(n), t(e);
            });
        });
      };
    !(function(n) {
      const t = e.collection('userclients');
      t.find({ isDeleted: !1 }).toArray(function(e, t) {
        r.equal(e, null), n(t);
      });
    })(r => {
      const s = (n, e, t) => {
        n.currentClientId = '';
        const o = n.dn.rdns;
        for (let e = 0; e < o.length; e++) {
          const t = o[e];
          for (let e in t.attrs)
            'o' === e && (n.currentClientId = t.attrs.o.value);
        }
        return t();
      };
      for (let c = 0; c < r.length; c++) {
        const d = r[c];
        let u = `ou=users,o=${d._id},dc=authing,dc=cn`;
        const l = `o=${d._id}, ou=users, dc=authing, dc=cn`;
        o.bind(u, function(n, e, t) {
          return e.end(), t();
        });
        const a = (e, t, o) =>
            e.connection.ldap.bindDN.equals(u)
              ? o()
              : o(new n.InsufficientAccessRightsError()),
          f = [a, s];
        o.search(l, f, async function(n, e, o) {
          const r = n.filter.attribute,
            s = n.filter.value,
            c = {
              cn: ['username', 'email', 'phone', 'unionid'],
              gid: ['_id'],
              uid: ['_id'],
            };
          let d = { registerInClient: t(n.currentClientId) };
          if (c[r]) {
            const o = c[r];
            for (let r = 0; r < o.length; r++) {
              const c = o[r];
              d[c] = '_id' === c ? t(s) : s;
              const u = await i(d);
              if (u && u.length > 0) {
                const t = u[0],
                  o = t.username || t.email || t.phone || t.unionid,
                  r = `cn=${o},uid=${t._id}, ou=users, o=${
                    n.currentClientId
                  }, dc=authing, dc=cn`;
                (t.cn = o),
                  (t.gid = t._id),
                  (t.uid = t._id),
                  delete t.__v,
                  delete t.isDeleted,
                  delete t.salt,
                  e.send({ dn: r, attributes: t });
                break;
              }
              delete d[c];
            }
          }
          return e.end(), o();
        }),
          o.add(l, f, async function(t, o, r) {
            const i = t.dn.rdns[0].cn;
            return (
              console.log(i, t.dn.rdns[0]),
              t.dn.rdns[0].cn
                ? (await ((s = {
                    username: i,
                    nickname: i,
                    unionid: i,
                    isDeleted: !1,
                    isBlocked: !1,
                    createdAt: Date.now,
                    updatedAt: Date.now,
                    photo: 'https://usercontents.authing.cn/authing-avatar.png',
                    registerInClient: t.currentClientId,
                    registerMethod: 'sso:ldap-add',
                  }),
                  new Promise((n, t) => {
                    const o = e.collection('users');
                    o.insertMany(s, (e, o) => {
                      e && t(e), n(o);
                    });
                  })),
                  o.end(),
                  r())
                : r(new n.ConstraintViolationError('cn required'))
            );
            var s;
          }),
          o.del(l, f, async function(e, t, o) {
            return (
              console.log(e.dn.rdns[0].cn),
              e.dn.rdns[0].cn
                ? (t.end(), o())
                : o(new n.NoSuchObjectError(e.dn.toString()))
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
