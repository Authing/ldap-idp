!(function(n) {
  'function' == typeof define && define.amd ? define(n) : n();
})(function() {
  'use strict';
  const n = require('ldapjs'),
    e = require('mongodb').MongoClient,
    t = require('mongodb').ObjectId,
    r = require('./ldapdb.json'),
    i = require('assert'),
    o = require('authing-js-sdk'),
    c = [
      'mongodb://',
      r.user + ':' + r.password + '@',
      r.ip,
      ':',
      r.port,
      '/',
      r.dbname,
    ].join('');
  e.connect(c, function(n, e) {
    i.equal(null, n), console.log('Connected successfully to server');
    const t = e.db(r.dbname);
    s(t);
  });
  const s = e => {
    const r = n.createServer(),
      c = function(n) {
        return new Promise((t, r) => {
          const i = e.collection('users');
          (n.isDeleted = !1),
            i.find(n).toArray(function(n, e) {
              n && r(n), t(e);
            });
        });
      };
    !(function(n) {
      const t = e.collection('userclients');
      t.find({ isDeleted: !1 }).toArray(function(e, t) {
        i.equal(e, null), n(t);
      });
    })(i => {
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
      for (let d = 0; d < i.length; d++) {
        const u = i[d];
        let l = `ou=users,o=${u._id},dc=authing,dc=cn`;
        const a = `o=${u._id}, ou=users, dc=authing, dc=cn`;
        r.bind(l, function(n, e, t) {
          return e.end(), t();
        });
        const f = (e, t, r) =>
            e.connection.ldap.bindDN.equals(l)
              ? r()
              : r(new n.InsufficientAccessRightsError()),
          g = [f, s];
        r.search(a, g, async function(n, e, r) {
          const i = n.filter.attribute,
            o = n.filter.value,
            s = {
              cn: ['username', 'email', 'phone', 'unionid'],
              gid: ['_id'],
              uid: ['_id'],
            };
          let d = { registerInClient: t(n.currentClientId) };
          if (s[i]) {
            const r = s[i];
            for (let i = 0; i < r.length; i++) {
              const s = r[i];
              d[s] = '_id' === s ? t(o) : o;
              const u = await c(d);
              if (u && u.length > 0) {
                const t = u[0],
                  r = t.username || t.email || t.phone || t.unionid,
                  i = `cn=${r},uid=${t._id}, ou=users, o=${
                    n.currentClientId
                  }, dc=authing, dc=cn`;
                (t.cn = r),
                  (t.gid = t._id),
                  (t.uid = t._id),
                  delete t.__v,
                  delete t.isDeleted,
                  delete t.salt,
                  e.send({ dn: i, attributes: t });
                break;
              }
              delete d[s];
            }
          }
          return e.end(), r();
        }),
          r.add(a, g, async function(e, r, i) {
            const s = e.dn.rdns[0].attrs.cn;
            if (!e.dn.rdns[0].attrs.cn)
              return i(new n.ConstraintViolationError('cn required'));
            const d = await c({
              registerInClient: t(e.currentClientId),
              isDeleted: !1,
              unionid: s.value,
            });
            if (d && d.length > 0)
              return i(new n.EntryAlreadyExistsError(e.dn.toString()));
            try {
              const t = await new o({
                clientId: e.currentClientId,
                secret: '03bb8b2fca823137c7dec63fd0029fc2',
              });
              await t.register({
                username: s.value,
                nickname: s.value,
                unionid: s.value,
                registerMethod: 'sso:ldap-add',
              });
            } catch (e) {
              return i(new n.UnavailableError(e.toString()));
            }
            return r.end(), i();
          }),
          r.del(a, g, async function(r, i, o) {
            const s = r.dn.rdns[0].attrs.cn;
            if (!r.dn.rdns[0].attrs.cn)
              return o(new n.NoSuchObjectError(r.dn.toString()));
            const d = await c({
              registerInClient: t(r.currentClientId),
              isDeleted: !1,
              unionid: s.value,
            });
            if (!d || 0 === d.length)
              return o(new n.NoSuchObjectError(r.dn.toString()));
            try {
              await ((u = {
                registerInClient: t(r.currentClientId),
                unionid: s.value,
              }),
              new Promise((n, t) => {
                const r = e.collection('users');
                (u.isDeleted = !1),
                  r.updateOne(u, { $set: { isDeleted: !0 } }),
                  c(u)
                    .then(e => {
                      n(e);
                    })
                    .catch(n => {
                      t(n);
                    });
              }));
            } catch (e) {
              return o(new n.UnavailableError(e.toString()));
            }
            var u;
            return i.end(), o();
          });
      }
      r.listen(1389, function() {
        console.log('LDAP server up at: %s', r.url);
      });
    });
  };
});
//# sourceMappingURL=ldap-idp.umd.production.js.map
