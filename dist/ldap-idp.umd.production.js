!(function(e) {
  'function' == typeof define && define.amd ? define(e) : e();
})(function() {
  'use strict';
  const e = require('ldapjs'),
    n = require('mongodb').MongoClient,
    t = require('mongodb').ObjectId,
    r = require('./ldapdb.json'),
    i = require('assert'),
    s = require('authing-js-sdk'),
    o = [
      'mongodb://',
      r.user + ':' + r.password + '@',
      r.ip,
      ':',
      r.port,
      '/',
      r.dbname,
    ].join('');
  n.connect(o, function(e, n) {
    i.equal(null, e), console.log('Connected successfully to server');
    const t = n.db(r.dbname);
    c(t);
  });
  const c = n => {
    const r = e.createServer(),
      o = function(e) {
        return new Promise((t, r) => {
          const i = n.collection('users');
          (e.isDeleted = !1),
            i.find(e).toArray(function(e, n) {
              e && r(e), t(n);
            });
        });
      };
    !(function(e) {
      const t = n.collection('userclients');
      t.find({ isDeleted: !1 }).toArray(function(n, t) {
        i.equal(n, null), e(t);
      });
    })(i => {
      const c = (e, n, t) => {
        e.currentClientId = '';
        const r = e.dn.rdns;
        for (let n = 0; n < r.length; n++) {
          const t = r[n];
          for (let n in t.attrs)
            'o' === n && (e.currentClientId = t.attrs.o.value);
        }
        return t();
      };
      for (let d = 0; d < i.length; d++) {
        const a = i[d] || {};
        let l = `ou=users,o=${a._id},dc=authing,dc=cn`;
        const u = `ou=users, o=${a._id}, dc=authing, dc=cn`;
        r.bind(l, async function(n, r, i) {
          const c = n.dn.rdns[1].attrs;
          let d = '';
          if (c.o) d = c.o.value;
          else {
            const e = n.dn.rdns;
            for (let n = 0; n < e.length; n++) {
              const t = e[n];
              for (let e in t.attrs) 'o' === e && (d = t.attrs.o.value);
            }
          }
          console.log(n.dn.rdns.toString());
          const l = n.dn.rdns.toString();
          if (l.indexOf('uid=') > -1)
            try {
              const r = n.dn.rdns;
              let c = '';
              for (let e = 0; e < r.length; e++) {
                const n = r[e];
                for (let e in n.attrs) 'uid' === e && (c = n.attrs.uid.value);
              }
              const l = await o({ registerInClient: t(d), _id: t(c) }),
                u = l[0];
              if (u.password && d.toString() === a._id.toString()) {
                const e = await new s({ clientId: d, secret: a.secret }),
                  t = { username: u.username, password: n.credentials };
                await e.login(t);
              }
            } catch (n) {
              return i(new e.InvalidCredentialsError(JSON.stringify(n)));
            }
          else if (
            d.toString() !== a._id.toString() ||
            n.credentials.toString() !== a.secret.toString()
          )
            return i(new e.InvalidCredentialsError());
          return r.end(), i();
        });
        const f = (n, t, r) =>
            n.connection.ldap.bindDN.equals(l)
              ? r()
              : r(new e.InsufficientAccessRightsError()),
          g = [f, c];
        r.search(u, g, async function(e, n, r) {
          const i = e.filter.attribute,
            s = e.filter.value || '*',
            c = { cn: 'username', gid: '_id', uid: '_id' };
          let d,
            a = { registerInClient: t(e.currentClientId) };
          if (((e.users = {}), c[i])) {
            const r = c[i];
            (a[r] = '_id' === r ? t(s) : s), (d = await o(a));
            const l = d[0],
              u = l.username,
              f = `cn=${u},uid=${l._id}, ou=users, o=${
                e.currentClientId
              }, dc=authing, dc=cn`;
            (l.cn = u),
              (l.gid = l._id),
              (l.uid = l._id),
              (l.objectclass = 'users'),
              delete l.__v,
              delete l.isDeleted,
              delete l.salt,
              n.send({ dn: f, attributes: l });
          } else {
            d = await o(a);
            for (var l = 0; l < d.length; l++) {
              const t = d[l],
                r = t.username,
                i = `cn=${r},uid=${t._id}, ou=users, o=${
                  e.currentClientId
                }, dc=authing, dc=cn`;
              (t.cn = r),
                (t.gid = t._id),
                (t.uid = t._id),
                (t.objectclass = 'users'),
                delete t.__v,
                delete t.isDeleted,
                delete t.salt,
                (e.users[i] = { dn: i, attributes: t }),
                Object.keys(e.users).forEach(function(t) {
                  e.filter.matches(e.users[t].attributes) && n.send(e.users[t]);
                });
            }
          }
          return n.end(), r();
        }),
          r.add(u, g, async function(n, r, i) {
            const c = n.dn.rdns[0].attrs.cn;
            if (!n.dn.rdns[0].attrs.cn)
              return i(new e.ConstraintViolationError('cn required'));
            const d = await o({
              registerInClient: t(n.currentClientId),
              isDeleted: !1,
              username: c.value,
            });
            if (d && d.length > 0)
              return i(new e.EntryAlreadyExistsError(n.dn.toString()));
            try {
              const t = await new s({
                clientId: n.currentClientId,
                secret: a.secret,
              });
              await t.register({
                username: c.value,
                nickname: c.value,
                unionid: `ldap|${c.value}`,
                registerMethod: 'ldap:sso::from-ldapadd',
              });
            } catch (n) {
              return i(new e.UnavailableError(n.toString()));
            }
            return r.end(), i();
          }),
          r.del(u, g, async function(r, i, s) {
            const c = r.dn.rdns[0].attrs.cn;
            if (!r.dn.rdns[0].attrs.cn)
              return s(new e.NoSuchObjectError(r.dn.toString()));
            const d = await o({
              registerInClient: t(r.currentClientId),
              isDeleted: !1,
              username: c.value,
            });
            if (!d || 0 === d.length)
              return s(new e.NoSuchObjectError(r.dn.toString()));
            try {
              await ((a = {
                registerInClient: t(r.currentClientId),
                username: c.value,
              }),
              new Promise((e, t) => {
                const r = n.collection('users');
                (a.isDeleted = !1),
                  r.updateOne(a, { $set: { isDeleted: !0 } }),
                  o(a)
                    .then(n => {
                      e(n);
                    })
                    .catch(e => {
                      t(e);
                    });
              }));
            } catch (n) {
              return s(new e.UnavailableError(n.toString()));
            }
            var a;
            return i.end(), s();
          }),
          r.modify(u, g, async function(n, r, i) {
            const c = n.dn.rdns[0].attrs.cn;
            if (!n.dn.rdns[0].attrs.cn)
              return i(new e.NoSuchObjectError(n.dn.toString()));
            if (!n.changes.length)
              return i(new e.ProtocolError('changes required'));
            const d = await o({
              registerInClient: t(n.currentClientId),
              isDeleted: !1,
              username: c.value,
            });
            if (!d || 0 === d.length)
              return i(new e.NoSuchObjectError(n.dn.toString()));
            const l = d[0];
            let u, f;
            for (var g = 0; g < n.changes.length; g++)
              switch (
                ((u = n.changes[g].modification), n.changes[g].operation)
              ) {
                case 'replace':
                  const t = {
                      userpassword: 'password',
                      mail: 'email',
                      cn: ['username'],
                    },
                    r = ['gid', 'uid', '_id'];
                  if (r.indexOf(u.type) > -1)
                    return i(
                      new e.UnwillingToPerformError(
                        `${u.type} is not allowed to modify`
                      )
                    );
                  let o = u.type;
                  t[u.type] && (o = t[u.type]);
                  try {
                    if (
                      ((f =
                        f ||
                        (await new s({
                          clientId: n.currentClientId,
                          secret: a.secret,
                        }))),
                      o instanceof String || 'string' == typeof o)
                    ) {
                      let e = { _id: l._id };
                      const n = o;
                      (e[n] = u.vals[0]), await f.update(e);
                    } else {
                      let e = { _id: d[0]._id };
                      for (let n = 0; n < o.length; n++) e[o[n]] = u.vals[0];
                      await f.update(e);
                    }
                  } catch (n) {
                    return i(new e.UnavailableError(n.toString()));
                  }
                  break;
                case 'add':
                case 'delete':
                  return i(
                    new e.UnwillingToPerformError('only replace allowed')
                  );
              }
            return r.end(), i();
          });
      }
      r.listen(1389, function() {
        console.log('LDAP server up at: %s', r.url);
      });
    });
  };
});
//# sourceMappingURL=ldap-idp.umd.production.js.map
