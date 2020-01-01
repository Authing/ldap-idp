'use strict';
const e = require('ldapjs'),
  t = require('mongodb').MongoClient,
  n = require('mongodb').ObjectId,
  r = require('./ldapdb.json'),
  s = require('assert'),
  i = require('authing-js-sdk'),
  o = `mongodb://${r.user}:${r.password}@${r.replicaSet.addr}/${
    r.dbname
  }?readPreference=secondaryPreferred&replicaSet=${r.replicaSet.name}`;
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
    },
    c = function(s) {
      let c = `ou=users,o=${s._id},dc=authing,dc=cn`;
      const a = `ou=users, o=${s._id}, dc=authing, dc=cn`;
      r.bind(c, async function(t, r, c) {
        const a = t.dn.rdns[1].attrs;
        let d = '';
        if (a.o) d = a.o.value;
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
            let a = '';
            for (let e = 0; e < r.length; e++) {
              const t = r[e];
              for (let e in t.attrs) 'uid' === e && (a = t.attrs.uid.value);
            }
            const l = await o({ registerInClient: n(d), _id: n(a) }),
              u = l[0];
            if (u.password && d.toString() === s._id.toString()) {
              const e = await new i({ clientId: d, secret: s.secret }),
                n = { username: u.username, password: t.credentials };
              await e.login(n);
            }
          } catch (t) {
            return c(new e.InvalidCredentialsError(JSON.stringify(t)));
          }
        else if (
          d.toString() !== s._id.toString() ||
          t.credentials.toString() !== s.secret.toString()
        )
          return c(new e.InvalidCredentialsError());
        return r.end(), c();
      });
      const d = [
        (t, n, r) =>
          t.connection.ldap.bindDN.equals(c)
            ? r()
            : r(new e.InsufficientAccessRightsError()),
        (e, t, n) => {
          e.currentClientId = '';
          const r = e.dn.rdns;
          for (let t = 0; t < r.length; t++) {
            const n = r[t];
            for (let t in n.attrs)
              'o' === t && (e.currentClientId = n.attrs.o.value);
          }
          return n();
        },
      ];
      r.search(a, d, async function(e, t, r) {
        const s = e.filter.attribute,
          i = e.filter.value || '*',
          c = { cn: 'username', gid: '_id', uid: '_id' };
        let a,
          d = { registerInClient: n(e.currentClientId) };
        if (((e.users = {}), c[s])) {
          const r = c[s];
          (d[r] = '_id' === r ? n(i) : i), (a = await o(d));
          const l = a[0],
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
          a = await o(d);
          for (var l = 0; l < a.length; l++) {
            const n = a[l],
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
        r.add(a, d, async function(t, r, c) {
          const a = t.dn.rdns[0].attrs.cn;
          if (!t.dn.rdns[0].attrs.cn)
            return c(new e.ConstraintViolationError('cn required'));
          const d = await o({
            registerInClient: n(t.currentClientId),
            isDeleted: !1,
            username: a.value,
          });
          if (d && d.length > 0)
            return c(new e.EntryAlreadyExistsError(t.dn.toString()));
          try {
            const n = await new i({
              clientId: t.currentClientId,
              secret: s.secret,
            });
            await n.register({
              username: a.value,
              nickname: a.value,
              unionid: `ldap|${a.value}`,
              registerMethod: 'ldap:sso::from-ldapadd',
            });
          } catch (t) {
            return c(new e.UnavailableError(t.toString()));
          }
          return r.end(), c();
        }),
        r.del(a, d, async function(r, s, i) {
          const c = r.dn.rdns[0].attrs.cn;
          if (!r.dn.rdns[0].attrs.cn)
            return i(new e.NoSuchObjectError(r.dn.toString()));
          const a = await o({
            registerInClient: n(r.currentClientId),
            isDeleted: !1,
            username: c.value,
          });
          if (!a || 0 === a.length)
            return i(new e.NoSuchObjectError(r.dn.toString()));
          try {
            await ((d = {
              registerInClient: n(r.currentClientId),
              username: c.value,
            }),
            new Promise((e, n) => {
              const r = t.collection('users');
              (d.isDeleted = !1),
                r.updateOne(d, { $set: { isDeleted: !0 } }),
                o(d)
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
          var d;
          return s.end(), i();
        }),
        r.modify(a, d, async function(t, r, c) {
          const a = t.dn.rdns[0].attrs.cn;
          if (!t.dn.rdns[0].attrs.cn)
            return c(new e.NoSuchObjectError(t.dn.toString()));
          if (!t.changes.length)
            return c(new e.ProtocolError('changes required'));
          const d = await o({
            registerInClient: n(t.currentClientId),
            isDeleted: !1,
            username: a.value,
          });
          if (!d || 0 === d.length)
            return c(new e.NoSuchObjectError(t.dn.toString()));
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
                  r = ['gid', 'uid', '_id', 'userpassword'];
                if (r.indexOf(u.type) > -1)
                  return c(
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
                        secret: s.secret,
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
                  return c(new e.UnavailableError(JSON.stringify(t)));
                }
                break;
              case 'add':
              case 'delete':
                return c(new e.UnwillingToPerformError('only replace allowed'));
            }
          return r.end(), c();
        });
    };
  !(function(e) {
    const n = t.collection('userpools');
    n.find({ isDeleted: !1 }).toArray(function(t, n) {
      s.equal(t, null), e(n);
    });
  })(e => {
    for (let t = 0; t < e.length; t++) {
      const n = e[t] || {};
      c(n);
    }
    const n = t.collection('userpools'),
      s = n.watch();
    s.on('change', e => {
      const t = e.operationType;
      if ('insert' === t) {
        const t = e.fullDocument;
        console.log('add client to ldap', t), c(t);
      }
    }),
      r.listen(1389, function() {
        console.log('LDAP server up at: %s', r.url);
      });
  });
};
//# sourceMappingURL=ldap-idp.cjs.production.js.map
