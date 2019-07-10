const e = require('ldapjs'),
  t = require('mongodb').MongoClient,
  n = require('mongodb').ObjectId,
  r = require('./ldapdb.json'),
  s = require('assert'),
  i = require('authing-js-sdk'),
  o = [
    'mongodb://',
    r.user + ':' + r.password + '@',
    r.ip,
    ':',
    r.port,
    '/',
    r.dbname,
  ].join('');
t.connect(o, function(e, t) {
  s.equal(null, e), console.log('Connected successfully to server');
  const n = t.db(r.dbname);
  c(n);
});
const c = t => {
  const r = e.createServer(),
    o = function(e) {
      return new Promise((n, r) => {
        const s = t.collection('users');
        (e.isDeleted = !1),
          s.find(e).toArray(function(e, t) {
            e && r(e), n(t);
          });
      });
    };
  !(function(e) {
    const n = t.collection('userclients');
    n.find({ isDeleted: !1 }).toArray(function(t, n) {
      s.equal(t, null), e(n);
    });
  })(s => {
    const c = (e, t, n) => {
      e.currentClientId = '';
      const r = e.dn.rdns;
      for (let t = 0; t < r.length; t++) {
        const n = r[t];
        for (let t in n.attrs)
          'o' === t && (e.currentClientId = n.attrs.o.value);
      }
      return n();
    };
    for (let d = 0; d < s.length; d++) {
      const a = s[d] || {};
      let l = `ou=users,o=${a._id},dc=authing,dc=cn`;
      const u = `ou=users, o=${a._id}, dc=authing, dc=cn`;
      r.bind(l, async function(t, r, s) {
        const c = t.dn.rdns[1].attrs;
        let d = '';
        if (c.o) d = c.o.value;
        else {
          const e = t.dn.rdns;
          for (let t = 0; t < e.length; t++) {
            const n = e[t];
            for (let e in n.attrs) 'o' === e && (d = n.attrs.o.value);
          }
        }
        console.log(t.dn.rdns.toString());
        const l = t.dn.rdns.toString();
        if (l.indexOf('uid=') > -1)
          try {
            const r = t.dn.rdns;
            let c = '';
            for (let e = 0; e < r.length; e++) {
              const t = r[e];
              for (let e in t.attrs) 'uid' === e && (c = t.attrs.uid.value);
            }
            const l = await o({ registerInClient: n(d), _id: n(c) }),
              u = l[0];
            if (u.password && d.toString() === a._id.toString()) {
              const e = await new i({ clientId: d, secret: a.secret }),
                n = { username: u.username, password: t.credentials };
              await e.login(n);
            }
          } catch (t) {
            return s(new e.InvalidCredentialsError(JSON.stringify(t)));
          }
        else if (
          d.toString() !== a._id.toString() ||
          t.credentials.toString() !== a.secret.toString()
        )
          return s(new e.InvalidCredentialsError());
        return r.end(), s();
      });
      const g = (t, n, r) =>
          t.connection.ldap.bindDN.equals(l)
            ? r()
            : r(new e.InsufficientAccessRightsError()),
        f = [g, c];
      r.search(u, f, async function(e, t, r) {
        const s = e.filter.attribute,
          i = e.filter.value || '*',
          c = { cn: 'username', gid: '_id', uid: '_id' };
        let d,
          a = { registerInClient: n(e.currentClientId) };
        if (((e.users = {}), c[s])) {
          const r = c[s];
          (a[r] = '_id' === r ? n(i) : i), (d = await o(a));
          const l = d[0],
            u = l.username,
            g = `cn=${u},uid=${l._id}, ou=users, o=${
              e.currentClientId
            }, dc=authing, dc=cn`;
          (l.cn = u),
            (l.gid = l._id),
            (l.uid = l._id),
            (l.objectclass = 'users'),
            delete l.__v,
            delete l.isDeleted,
            delete l.salt,
            t.send({ dn: g, attributes: l });
        } else {
          d = await o(a);
          for (var l = 0; l < d.length; l++) {
            const n = d[l],
              r = n.username,
              s = `cn=${r},uid=${n._id}, ou=users, o=${
                e.currentClientId
              }, dc=authing, dc=cn`;
            (n.cn = r),
              (n.gid = n._id),
              (n.uid = n._id),
              (n.objectclass = 'users'),
              delete n.__v,
              delete n.isDeleted,
              delete n.salt,
              (e.users[s] = { dn: s, attributes: n }),
              Object.keys(e.users).forEach(function(n) {
                e.filter.matches(e.users[n].attributes) && t.send(e.users[n]);
              });
          }
        }
        return t.end(), r();
      }),
        r.add(u, f, async function(t, r, s) {
          const c = t.dn.rdns[0].attrs.cn;
          if (!t.dn.rdns[0].attrs.cn)
            return s(new e.ConstraintViolationError('cn required'));
          const d = await o({
            registerInClient: n(t.currentClientId),
            isDeleted: !1,
            username: c.value,
          });
          if (d && d.length > 0)
            return s(new e.EntryAlreadyExistsError(t.dn.toString()));
          try {
            const n = await new i({
              clientId: t.currentClientId,
              secret: a.secret,
            });
            await n.register({
              username: c.value,
              nickname: c.value,
              unionid: `ldap|${c.value}`,
              registerMethod: 'ldap:sso::from-ldapadd',
            });
          } catch (t) {
            return s(new e.UnavailableError(t.toString()));
          }
          return r.end(), s();
        }),
        r.del(u, f, async function(r, s, i) {
          const c = r.dn.rdns[0].attrs.cn;
          if (!r.dn.rdns[0].attrs.cn)
            return i(new e.NoSuchObjectError(r.dn.toString()));
          const d = await o({
            registerInClient: n(r.currentClientId),
            isDeleted: !1,
            username: c.value,
          });
          if (!d || 0 === d.length)
            return i(new e.NoSuchObjectError(r.dn.toString()));
          try {
            await ((a = {
              registerInClient: n(r.currentClientId),
              username: c.value,
            }),
            new Promise((e, n) => {
              const r = t.collection('users');
              (a.isDeleted = !1),
                r.updateOne(a, { $set: { isDeleted: !0 } }),
                o(a)
                  .then(t => {
                    e(t);
                  })
                  .catch(e => {
                    n(e);
                  });
            }));
          } catch (t) {
            return i(new e.UnavailableError(t.toString()));
          }
          var a;
          return s.end(), i();
        }),
        r.modify(u, f, async function(t, r, s) {
          const c = t.dn.rdns[0].attrs.cn;
          if (!t.dn.rdns[0].attrs.cn)
            return s(new e.NoSuchObjectError(t.dn.toString()));
          if (!t.changes.length)
            return s(new e.ProtocolError('changes required'));
          const d = await o({
            registerInClient: n(t.currentClientId),
            isDeleted: !1,
            username: c.value,
          });
          if (!d || 0 === d.length)
            return s(new e.NoSuchObjectError(t.dn.toString()));
          const l = d[0];
          let u, g;
          for (var f = 0; f < t.changes.length; f++)
            switch (((u = t.changes[f].modification), t.changes[f].operation)) {
              case 'replace':
                const n = {
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
                let o = u.type;
                n[u.type] && (o = n[u.type]);
                try {
                  if (
                    ((g =
                      g ||
                      (await new i({
                        clientId: t.currentClientId,
                        secret: a.secret,
                      }))),
                    o instanceof String || 'string' == typeof o)
                  ) {
                    let e = { _id: l._id };
                    const t = o;
                    (e[t] = u.vals[0]), await g.update(e);
                  } else {
                    let e = { _id: d[0]._id };
                    for (let t = 0; t < o.length; t++) e[o[t]] = u.vals[0];
                    await g.update(e);
                  }
                } catch (t) {
                  return s(new e.UnavailableError(t.toString()));
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
//# sourceMappingURL=ldap-idp.es.production.js.map
