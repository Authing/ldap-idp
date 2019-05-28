'use strict';
const n = require('ldapjs'),
  e = require('mongodb').MongoClient,
  t = require('mongodb').ObjectId,
  r = require('./ldapdb.json'),
  o = require('assert'),
  i = [
    'mongodb://',
    r.user + ':' + r.password + '@',
    r.ip,
    ':',
    r.port,
    '/',
    r.dbname,
  ].join('');
e.connect(i, function(n, e) {
  o.equal(null, n), console.log('Connected successfully to server');
  const t = e.db(r.dbname);
  s(t);
});
const s = e => {
  const r = n.createServer(),
    i = function(n) {
      return new Promise((t, r) => {
        const o = e.collection('users');
        (n.isDeleted = !1),
          o.find(n).toArray(function(n, e) {
            n && r(n), t(e);
          });
      });
    };
  !(function(n) {
    const t = e.collection('userclients');
    t.find({ isDeleted: !1 }).toArray(function(e, t) {
      o.equal(e, null), n(t);
    });
  })(o => {
    const s = (n, e, t) => {
      n.currentClientId = '';
      const r = n.dn.rdns;
      for (let e = 0; e < r.length; e++) {
        const t = r[e];
        for (let e in t.attrs)
          'o' === e && (n.currentClientId = t.attrs.o.value);
      }
      return t();
    };
    for (let c = 0; c < o.length; c++) {
      const d = o[c];
      let u = `ou=users,o=${d._id},dc=authing,dc=cn`;
      const l = `o=${d._id}, ou=users, dc=authing, dc=cn`;
      r.bind(u, function(n, e, t) {
        return e.end(), t();
      });
      const a = (e, t, r) =>
          e.connection.ldap.bindDN.equals(u)
            ? r()
            : r(new n.InsufficientAccessRightsError()),
        g = [a, s];
      r.search(l, g, async function(n, e, r) {
        const o = n.filter.attribute,
          s = n.filter.value,
          c = {
            cn: ['username', 'email', 'phone', 'unionid'],
            gid: ['_id'],
            uid: ['_id'],
          };
        let d = { registerInClient: t(n.currentClientId) };
        if (c[o]) {
          const r = c[o];
          for (let o = 0; o < r.length; o++) {
            const c = r[o];
            d[c] = '_id' === c ? t(s) : s;
            const u = await i(d);
            if (u && u.length > 0) {
              const t = u[0],
                r = t.username || t.email || t.phone || t.unionid,
                o = `cn=${r},uid=${t._id}, ou=users, o=${
                  n.currentClientId
                }, dc=authing, dc=cn`;
              (t.cn = r),
                (t.gid = t._id),
                (t.uid = t._id),
                delete t.__v,
                delete t.isDeleted,
                delete t.salt,
                e.send({ dn: o, attributes: t });
              break;
            }
            delete d[c];
          }
        }
        return e.end(), r();
      }),
        r.add(l, g, async function(t, r, o) {
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
                  const r = e.collection('users');
                  r.insertMany(s, (e, r) => {
                    e && t(e), n(r);
                  });
                })),
                r.end(),
                o())
              : o(new n.ConstraintViolationError('cn required'))
          );
          var s;
        }),
        r.del(l, g, async function(e, t, r) {
          return (
            console.log(e.dn.rdns[0].cn),
            e.dn.rdns[0].cn
              ? (t.end(), r())
              : r(new n.NoSuchObjectError(e.dn.toString()))
          );
        });
    }
    r.listen(1389, function() {
      console.log('LDAP server up at: %s', r.url);
    });
  });
};
//# sourceMappingURL=ldap-idp.cjs.production.js.map
