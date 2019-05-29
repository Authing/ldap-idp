'use strict';
const e = require('ldapjs'),
  n = require('mongodb').MongoClient,
  t = require('mongodb').ObjectId,
  r = require('./ldapdb.json'),
  s = require('assert'),
  i = require('authing-js-sdk'),
  c = [
    'mongodb://',
    r.user + ':' + r.password + '@',
    r.ip,
    ':',
    r.port,
    '/',
    r.dbname,
  ].join('');
n.connect(c, function(e, n) {
  s.equal(null, e), console.log('Connected successfully to server');
  const t = n.db(r.dbname);
  o(t);
});
const o = n => {
  const r = e.createServer(),
    c = function(e) {
      return new Promise((t, r) => {
        const s = n.collection('users');
        (e.isDeleted = !1),
          s.find(e).toArray(function(e, n) {
            e && r(e), t(n);
          });
      });
    };
  !(function(e) {
    const t = n.collection('userclients');
    t.find({ isDeleted: !1 }).toArray(function(n, t) {
      s.equal(n, null), e(t);
    });
  })(s => {
    const o = (e, n, t) => {
      e.currentClientId = '';
      const r = e.dn.rdns;
      for (let n = 0; n < r.length; n++) {
        const t = r[n];
        for (let n in t.attrs)
          'o' === n && (e.currentClientId = t.attrs.o.value);
      }
      return t();
    };
    for (let a = 0; a < s.length; a++) {
      const d = s[a];
      let l = `ou=users,o=${d._id},dc=authing,dc=cn`;
      const u = `o=${d._id}, ou=users, dc=authing, dc=cn`;
      r.bind(l, async function(n, t, r) {
        const s = n.dn.rdns[1].attrs;
        let i;
        return (
          s.o && (i = s.o.value),
          i.toString() !== d._id.toString() ||
          n.credentials.toString() !== d.secret.toString()
            ? r(new e.InvalidCredentialsError())
            : (t.end(), r())
        );
      });
      const g = (n, t, r) =>
          n.connection.ldap.bindDN.equals(l)
            ? r()
            : r(new e.InsufficientAccessRightsError()),
        f = [g, o];
      r.search(u, f, async function(r, s, i) {
        const o = r.filter.attribute,
          a = r.filter.value || '*',
          d = { cn: 'username', gid: '_id', uid: '_id' };
        let l,
          u = { registerInClient: t(r.currentClientId) };
        if (((r.users = {}), d[o])) {
          const e = d[o];
          (u[e] = '_id' === e ? t(a) : a), (l = await c(u));
          const n = l[0],
            i = n.username,
            g = `cn=${i},uid=${n._id}, ou=users, o=${
              r.currentClientId
            }, dc=authing, dc=cn`;
          (n.cn = i),
            (n.gid = n._id),
            (n.uid = n._id),
            (n.objectclass = 'users'),
            delete n.__v,
            delete n.isDeleted,
            delete n.salt,
            s.send({ dn: g, attributes: n });
        } else {
          l = await c(u);
          for (var g = 0; g < l.length; g++) {
            const t = l[g],
              c = t.username,
              o = `cn=${c},uid=${t._id}, ou=users, o=${
                r.currentClientId
              }, dc=authing, dc=cn`;
            let a;
            switch (
              ((t.cn = c),
              (t.gid = t._id),
              (t.uid = t._id),
              (t.objectclass = 'users'),
              delete t.__v,
              delete t.isDeleted,
              delete t.salt,
              (r.users[t._id] = { dn: o, attributes: t }),
              r.scope)
            ) {
              case 'base':
                return (
                  r.filter.matches(n[o]) && s.send({ dn: o, attributes: n[o] }),
                  s.end(),
                  i()
                );
              case 'one':
                a = function(n) {
                  if (r.dn.equals(n)) return !0;
                  var t = e.parseDN(n).parent();
                  return !!t && t.equals(r.dn);
                };
                break;
              case 'sub':
                a = function(e) {
                  return r.dn.equals(e) || r.dn.parentOf(e);
                };
            }
            Object.keys(r.users).forEach(function(e) {
              a(e) && r.filter.matches(r.users[e]) && s.send(r.users[e]);
            });
          }
        }
        return s.end(), i();
      }),
        r.add(u, f, async function(n, r, s) {
          const o = n.dn.rdns[0].attrs.cn;
          if (!n.dn.rdns[0].attrs.cn)
            return s(new e.ConstraintViolationError('cn required'));
          const a = await c({
            registerInClient: t(n.currentClientId),
            isDeleted: !1,
            username: o.value,
          });
          if (a && a.length > 0)
            return s(new e.EntryAlreadyExistsError(n.dn.toString()));
          try {
            const t = await new i({
              clientId: n.currentClientId,
              secret: d.secret,
            });
            await t.register({
              username: o.value,
              nickname: o.value,
              unionid: `ldap|${o.value}`,
              registerMethod: 'sso:ldap-add',
            });
          } catch (n) {
            return s(new e.UnavailableError(n.toString()));
          }
          return r.end(), s();
        }),
        r.del(u, f, async function(r, s, i) {
          const o = r.dn.rdns[0].attrs.cn;
          if (!r.dn.rdns[0].attrs.cn)
            return i(new e.NoSuchObjectError(r.dn.toString()));
          const a = await c({
            registerInClient: t(r.currentClientId),
            isDeleted: !1,
            username: o.value,
          });
          if (!a || 0 === a.length)
            return i(new e.NoSuchObjectError(r.dn.toString()));
          try {
            await ((d = {
              registerInClient: t(r.currentClientId),
              username: o.value,
            }),
            new Promise((e, t) => {
              const r = n.collection('users');
              (d.isDeleted = !1),
                r.updateOne(d, { $set: { isDeleted: !0 } }),
                c(d)
                  .then(n => {
                    e(n);
                  })
                  .catch(e => {
                    t(e);
                  });
            }));
          } catch (n) {
            return i(new e.UnavailableError(n.toString()));
          }
          var d;
          return s.end(), i();
        }),
        r.modify(u, f, async function(n, r, s) {
          const o = n.dn.rdns[0].attrs.cn;
          if (!n.dn.rdns[0].attrs.cn)
            return s(new e.NoSuchObjectError(n.dn.toString()));
          if (!n.changes.length)
            return s(new e.ProtocolError('changes required'));
          const a = await c({
            registerInClient: t(n.currentClientId),
            isDeleted: !1,
            username: o.value,
          });
          if (!a || 0 === a.length)
            return s(new e.NoSuchObjectError(n.dn.toString()));
          const l = a[0];
          let u, g;
          for (var f = 0; f < n.changes.length; f++)
            switch (((u = n.changes[f].modification), n.changes[f].operation)) {
              case 'replace':
                const t = {
                    userpassword: 'password',
                    mail: 'email',
                    cn: ['username'],
                  },
                  r = ['gid', 'uid', '_id'];
                if (r.indexOf(u.type) > -1)
                  return s(
                    new e.UnwillingToPerformError(
                      `${u.type} is not allowed to modify`
                    )
                  );
                let c = u.type;
                t[u.type] && (c = t[u.type]);
                try {
                  if (
                    ((g =
                      g ||
                      (await new i({
                        clientId: n.currentClientId,
                        secret: d.secret,
                      }))),
                    c instanceof String || 'string' == typeof c)
                  ) {
                    let e = { _id: l._id };
                    const n = c;
                    (e[n] = u.vals[0]), await g.update(e);
                  } else {
                    let e = { _id: a[0]._id };
                    for (let n = 0; n < c.length; n++) e[c[n]] = u.vals[0];
                    await g.update(e);
                  }
                } catch (n) {
                  return s(new e.UnavailableError(n.toString()));
                }
                break;
              case 'add':
              case 'delete':
                return s(new e.UnwillingToPerformError('only replace allowed'));
            }
          return r.end(), s();
        });
    }
    r.listen(1389, function() {
      console.log('LDAP server up at: %s', r.url);
    });
  });
};
//# sourceMappingURL=ldap-idp.cjs.production.js.map
