!(function(e) {
  'function' == typeof define && define.amd ? define(e) : e();
})(function() {
  'use strict';
  const e = require('ldapjs'),
    n = require('mongodb').MongoClient,
    t = require('mongodb').ObjectId,
    r = require('./ldapdb.json'),
    s = require('assert'),
    i = require('authing-js-sdk'),
    o = `mongodb://${r.user}:${r.password}@${r.replicaSet.addr}/${
      r.dbname
    }?readPreference=secondaryPreferred&replicaSet=${r.replicaSet.name}`;
  process.on('unhandledRejection', e => {
    console.log('全局reject'), console.log(e);
  }),
    n.connect(o, function(e, n) {
      s.equal(null, e), console.log('Connected successfully to server');
      const t = n.db(r.dbname);
      c(t);
    });
  const c = n => {
    const r = e.createServer(),
      o = function(e) {
        return new Promise((t, r) => {
          const s = n.collection('users');
          (e.isDeleted = !1),
            s.find(e).toArray(function(e, n) {
              e && r(e), t(n);
            });
        });
      },
      c = function(s) {
        let c = `ou=users,o=${s._id},dc=authing,dc=cn`;
        const d = `ou=users, o=${s._id}, dc=authing, dc=cn`;
        r.bind(c, async function(n, r, c) {
          const d = n.dn.rdns[1].attrs;
          let a = '';
          if (d.o) a = d.o.value;
          else {
            const e = n.dn.rdns;
            for (let n = 0; n < e.length; n++) {
              const t = e[n];
              for (let e in t.attrs) 'o' === e && (a = t.attrs.o.value);
            }
          }
          console.log(n.dn.rdns.toString());
          const l = n.dn.rdns.toString();
          if (l.indexOf('uid=') > -1)
            try {
              const r = n.dn.rdns;
              let d = '';
              for (let e = 0; e < r.length; e++) {
                const n = r[e];
                for (let e in n.attrs) 'uid' === e && (d = n.attrs.uid.value);
              }
              const l = await o({ registerInClient: t(a), _id: t(d) }),
                u = l[0];
              if (u.password && a.toString() === s._id.toString()) {
                const e = await new i({ clientId: a, secret: s.secret }),
                  t = { username: u.username, password: n.credentials };
                await e.login(t);
              }
            } catch (n) {
              return c(new e.InvalidCredentialsError(JSON.stringify(n)));
            }
          else if (
            a.toString() !== s._id.toString() ||
            n.credentials.toString() !== s.secret.toString()
          )
            return c(new e.InvalidCredentialsError());
          return r.end(), c();
        });
        const a = [
          (n, t, r) =>
            n.connection.ldap.bindDN.equals(c)
              ? r()
              : r(new e.InsufficientAccessRightsError()),
          (e, n, t) => {
            e.currentClientId = '';
            const r = e.dn.rdns;
            for (let n = 0; n < r.length; n++) {
              const t = r[n];
              for (let n in t.attrs)
                'o' === n && (e.currentClientId = t.attrs.o.value);
            }
            return t();
          },
        ];
        r.search(d, a, async function(e, n, r) {
          const s = e.filter.attribute,
            i = e.filter.value || '*',
            c = { cn: 'username', gid: '_id', uid: '_id' };
          let d,
            a = { registerInClient: t(e.currentClientId) };
          if (((e.users = {}), c[s])) {
            const r = c[s];
            (a[r] = '_id' === r ? t(i) : i), (d = await o(a));
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
                s = `cn=${r},uid=${t._id}, ou=users, o=${
                  e.currentClientId
                }, dc=authing, dc=cn`;
              (t.cn = r),
                (t.gid = t._id),
                (t.uid = t._id),
                (t.objectclass = 'users'),
                delete t.__v,
                delete t.isDeleted,
                delete t.salt,
                (e.users[s] = { dn: s, attributes: t }),
                Object.keys(e.users).forEach(function(t) {
                  e.filter.matches(e.users[t].attributes) && n.send(e.users[t]);
                });
            }
          }
          return n.end(), r();
        }),
          r.add(d, a, async function(n, r, c) {
            const d = n.dn.rdns[0].attrs.cn;
            if (!n.dn.rdns[0].attrs.cn)
              return c(new e.ConstraintViolationError('cn required'));
            const a = await o({
              registerInClient: t(n.currentClientId),
              isDeleted: !1,
              username: d.value,
            });
            if (a && a.length > 0)
              return c(new e.EntryAlreadyExistsError(n.dn.toString()));
            try {
              const t = await new i({
                clientId: n.currentClientId,
                secret: s.secret,
              });
              await t.register({
                username: d.value,
                nickname: d.value,
                unionid: `ldap|${d.value}`,
                registerMethod: 'ldap:sso::from-ldapadd',
              });
            } catch (n) {
              return c(new e.UnavailableError(n.toString()));
            }
            return r.end(), c();
          }),
          r.del(d, a, async function(r, s, i) {
            const c = r.dn.rdns[0].attrs.cn;
            if (!r.dn.rdns[0].attrs.cn)
              return i(new e.NoSuchObjectError(r.dn.toString()));
            const d = await o({
              registerInClient: t(r.currentClientId),
              isDeleted: !1,
              username: c.value,
            });
            if (!d || 0 === d.length)
              return i(new e.NoSuchObjectError(r.dn.toString()));
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
              return i(new e.UnavailableError(n.toString()));
            }
            var a;
            return s.end(), i();
          }),
          r.modify(d, a, async function(n, r, c) {
            const d = n.dn.rdns[0].attrs.cn;
            if (!n.dn.rdns[0].attrs.cn)
              return c(new e.NoSuchObjectError(n.dn.toString()));
            if (!n.changes.length)
              return c(new e.ProtocolError('changes required'));
            const a = await o({
              registerInClient: t(n.currentClientId),
              isDeleted: !1,
              username: d.value,
            });
            if (!a || 0 === a.length)
              return c(new e.NoSuchObjectError(n.dn.toString()));
            const l = a[0];
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
                    r = ['gid', 'uid', '_id', 'userpassword'];
                  if (r.indexOf(u.type) > -1)
                    return c(
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
                        (await new i({
                          clientId: n.currentClientId,
                          secret: s.secret,
                        }))),
                      o instanceof String || 'string' == typeof o)
                    ) {
                      let e = { _id: l._id };
                      const n = o;
                      (e[n] = u.vals[0]), await f.update(e);
                    } else {
                      let e = { _id: a[0]._id };
                      for (let n = 0; n < o.length; n++) e[o[n]] = u.vals[0];
                      await f.update(e);
                    }
                  } catch (n) {
                    return c(new e.UnavailableError(JSON.stringify(n)));
                  }
                  break;
                case 'add':
                case 'delete':
                  return c(
                    new e.UnwillingToPerformError('only replace allowed')
                  );
              }
            return r.end(), c();
          });
      };
    !(function(e) {
      const t = n.collection('userpools');
      t.find({ isDeleted: !1 }).toArray(function(n, t) {
        s.equal(n, null), e(t);
      });
    })(e => {
      for (let n = 0; n < e.length; n++) {
        const t = e[n] || {};
        c(t);
      }
      const t = n.collection('userpools'),
        s = t.watch();
      s.on('change', e => {
        const n = e.operationType;
        if ('insert' === n) {
          const n = e.fullDocument;
          console.log('add client to ldap', n), c(n);
        }
      }),
        r.listen(1389, function() {
          console.log('LDAP server up at: %s', r.url);
        });
    });
  };
});
//# sourceMappingURL=ldap-idp.umd.production.js.map
