'use strict';
const n = require('ldapjs'),
  e = require('mongodb').MongoClient,
  t = require('mongodb').ObjectId,
  r = require('./ldapdb.json'),
  i = require('assert'),
  o = require('authing-js-sdk'),
  s = [
    'mongodb://',
    r.user + ':' + r.password + '@',
    r.ip,
    ':',
    r.port,
    '/',
    r.dbname,
  ].join('');
e.connect(s, function(n, e) {
  i.equal(null, n), console.log('Connected successfully to server');
  const t = e.db(r.dbname);
  c(t);
});
const c = e => {
  const r = n.createServer(),
    s = function(n) {
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
  })(e => {
    const i = (n, e, t) => {
      n.currentClientId = '';
      const r = n.dn.rdns;
      for (let e = 0; e < r.length; e++) {
        const t = r[e];
        for (let e in t.attrs)
          'o' === e && (n.currentClientId = t.attrs.o.value);
      }
      return t();
    };
    for (let c = 0; c < e.length; c++) {
      const d = e[c];
      let u = `ou=users,o=${d._id},dc=authing,dc=cn`;
      const l = `o=${d._id}, ou=users, dc=authing, dc=cn`;
      r.bind(u, function(n, e, t) {
        return e.end(), t();
      });
      const a = (e, t, r) =>
          e.connection.ldap.bindDN.equals(u)
            ? r()
            : r(new n.InsufficientAccessRightsError()),
        f = [a, i];
      r.search(l, f, async function(n, e, r) {
        const i = n.filter.attribute,
          o = n.filter.value,
          c = {
            cn: ['username', 'email', 'phone', 'unionid'],
            gid: ['_id'],
            uid: ['_id'],
          };
        let d = { registerInClient: t(n.currentClientId) };
        if (c[i]) {
          const r = c[i];
          for (let i = 0; i < r.length; i++) {
            const c = r[i];
            d[c] = '_id' === c ? t(o) : o;
            const u = await s(d);
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
            delete d[c];
          }
        }
        return e.end(), r();
      }),
        r.add(l, f, async function(e, r, i) {
          const c = e.dn.rdns[0].attrs.cn;
          if (!e.dn.rdns[0].attrs.cn)
            return i(new n.ConstraintViolationError('cn required'));
          const d = await s({
            registerInClient: t(e.currentClientId),
            isDeleted: !1,
            unionid: c.value,
          });
          if (d && d.length > 0)
            return i(new n.EntryAlreadyExistsError(e.dn.toString()));
          try {
            const t = await new o({
              clientId: e.currentClientId,
              secret: '03bb8b2fca823137c7dec63fd0029fc2',
            });
            await t.register({
              username: c.value,
              nickname: c.value,
              unionid: c.value,
              registerMethod: 'sso:ldap-add',
            });
          } catch (e) {
            return i(new n.UnavailableError(e.toString()));
          }
          return r.end(), i();
        }),
        r.del(l, f, async function(e, t, r) {
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
