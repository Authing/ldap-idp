'use strict';
var e = {
  domainComponent: ['authing', 'cn'],
  authing: {
    graphqlEndPoint: { core: 'https://core.authing.cn/graphql' },
    passwordEncPublicKey:
      '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4xKeUgQ+Aoz7TLfAfs9+paePb\n5KIofVthEopwrXFkp8OCeocaTHt9ICjTT2QeJh6cZaDaArfZ873GPUn00eOIZ7Ae\n+TiA2BKHbCvloW3w5Lnqm70iSsUi5Fmu9/2+68GZRH9L7Mlh8cFksCicW2Y2W2uM\nGKl64GDcIq3au+aqJQIDAQAB\n-----END PUBLIC KEY-----',
  },
};
const n = require('ldapjs'),
  t = require('mongodb').MongoClient,
  r = require('mongodb').ObjectId,
  o = require('./ldapdb.json'),
  s = require('assert'),
  i = require('authing-js-sdk'),
  a = `mongodb://${o.user}:${o.password}@${o.replicaSet.addr}/${
    o.dbname
  }?readPreference=secondaryPreferred&replicaSet=${o.replicaSet.name}`;
function c(e, n = ',') {
  let t = e.map(e => 'dc=' + e),
    r = t.join(n);
  return r;
}
process.on('unhandledRejection', e => {
  console.log('全局reject'), console.log(e);
}),
  process.on('uncaughtException', function(e) {
    console.log(e);
  }),
  t.connect(a, function(e, n) {
    s.equal(null, e), console.log('Connected successfully to server');
    const t = n.db(o.dbname);
    l(t);
  });
const l = t => {
  const o = n.createServer(),
    a = function(e) {
      return new Promise((n, r) => {
        const o = t.collection('users');
        (e.isDeleted = !1),
          o.find(e).toArray(function(e, t) {
            e && r(e), n(t);
          });
      });
    },
    l = function(s) {
      let l = `ou=users,o=${s._id},${c(e.domainComponent)}`;
      const d = `ou=users, o=${s._id}, ${c(e.domainComponent, ', ')}`;
      o.bind(l, async function(t, o, c) {
        const l = t.dn.rdns[1].attrs;
        let d = '';
        if (l.o) d = l.o.value;
        else {
          const e = t.dn.rdns;
          for (let n = 0; n < e.length; n++) {
            const t = e[n];
            for (let e in t.attrs) 'o' === e && (d = t.attrs.o.value);
          }
        }
        console.log(t.dn.rdns.toString());
        const u = t.dn.rdns.toString();
        if (u.indexOf('uid=') > -1)
          try {
            const o = t.dn.rdns;
            let l = '';
            for (let e = 0; e < o.length; e++) {
              const n = o[e];
              for (let e in n.attrs) 'uid' === e && (l = n.attrs.uid.value);
            }
            const u = await a({ registerInClient: r(d), _id: r(l) }),
              g = u[0];
            if (g.password && d.toString() === s._id.toString()) {
              const n = new i({
                  userPoolId: d,
                  secret: s.secret,
                  host: {
                    user: e.authing.graphqlEndPoint.core,
                    oauth: e.authing.graphqlEndPoint.core,
                  },
                  passwordEncPublicKey: e.authing.passwordEncPublicKey,
                }),
                r = { username: g.username, password: t.credentials };
              await n.login(r);
            }
          } catch (e) {
            return c(new n.InvalidCredentialsError(JSON.stringify(e)));
          }
        else if (
          d.toString() !== s._id.toString() ||
          t.credentials.toString() !== s.secret.toString()
        )
          return c(new n.InvalidCredentialsError());
        return o.end(), c();
      });
      const u = [
        (e, t, r) =>
          e.connection.ldap.bindDN.equals(l)
            ? r()
            : r(new n.InsufficientAccessRightsError()),
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
      o.search(d, u, async function(n, t, o) {
        const s = n.filter.attribute,
          i = n.filter.value || '*',
          l = { cn: 'username', gid: '_id', uid: '_id' };
        let d,
          u = { registerInClient: r(n.currentClientId) };
        if (((n.users = {}), l[s])) {
          const o = l[s];
          (u[o] = '_id' === o ? r(i) : i), (d = await a(u));
          const g = d[0],
            f = g.username,
            h = `cn=${f},uid=${g._id}, ou=users, o=${n.currentClientId}, ${c(
              e.domainComponent,
              ', '
            )}`;
          (g.cn = f),
            (g.gid = g._id),
            (g.uid = g._id),
            (g.objectclass = 'users'),
            delete g.__v,
            delete g.isDeleted,
            delete g.salt,
            t.send({ dn: h, attributes: g });
        } else {
          d = await a(u);
          for (var g = 0; g < d.length; g++) {
            const r = d[g],
              o = r.username,
              s = `cn=${o},uid=${r._id}, ou=users, o=${n.currentClientId}, ${c(
                e.domainComponent,
                ', '
              )}`;
            (r.cn = o),
              (r.gid = r._id),
              (r.uid = r._id),
              (r.objectclass = 'users'),
              delete r.__v,
              delete r.isDeleted,
              delete r.salt,
              (n.users[s] = { dn: s, attributes: r }),
              Object.keys(n.users).forEach(function(e) {
                n.filter.matches(n.users[e].attributes) && t.send(n.users[e]);
              });
          }
        }
        return t.end(), o();
      }),
        o.add(d, u, async function(t, o, c) {
          const l = t.dn.rdns[0].attrs.cn;
          if (!t.dn.rdns[0].attrs.cn)
            return c(new n.ConstraintViolationError('cn required'));
          const d = await a({
            registerInClient: r(t.currentClientId),
            isDeleted: !1,
            username: l.value,
          });
          if (d && d.length > 0)
            return c(new n.EntryAlreadyExistsError(t.dn.toString()));
          try {
            const r = new i({
              userPoolId: t.currentClientId,
              secret: s.secret,
              host: {
                user: e.authing.graphqlEndPoint.core,
                oauth: e.authing.graphqlEndPoint.core,
              },
              passwordEncPublicKey: e.authing.passwordEncPublicKey,
            });
            await r.register({
              username: l.value,
              nickname: l.value,
              unionid: `ldap|${l.value}`,
              registerMethod: 'ldap:sso::from-ldapadd',
            });
          } catch (e) {
            return c(new n.UnavailableError(e.toString()));
          }
          return o.end(), c();
        }),
        o.del(d, u, async function(e, o, s) {
          const i = e.dn.rdns[0].attrs.cn;
          if (!e.dn.rdns[0].attrs.cn)
            return s(new n.NoSuchObjectError(e.dn.toString()));
          const c = await a({
            registerInClient: r(e.currentClientId),
            isDeleted: !1,
            username: i.value,
          });
          if (!c || 0 === c.length)
            return s(new n.NoSuchObjectError(e.dn.toString()));
          try {
            await ((l = {
              registerInClient: r(e.currentClientId),
              username: i.value,
            }),
            new Promise((e, n) => {
              const r = t.collection('users');
              (l.isDeleted = !1),
                r.updateOne(l, { $set: { isDeleted: !0 } }),
                a(l)
                  .then(n => {
                    e(n);
                  })
                  .catch(e => {
                    n(e);
                  });
            }));
          } catch (e) {
            return s(new n.UnavailableError(e.toString()));
          }
          var l;
          return o.end(), s();
        }),
        o.modify(d, u, async function(t, o, c) {
          const l = t.dn.rdns[0].attrs.cn;
          if (!t.dn.rdns[0].attrs.cn)
            return c(new n.NoSuchObjectError(t.dn.toString()));
          if (!t.changes.length)
            return c(new n.ProtocolError('changes required'));
          const d = await a({
            registerInClient: r(t.currentClientId),
            isDeleted: !1,
            username: l.value,
          });
          if (!d || 0 === d.length)
            return c(new n.NoSuchObjectError(t.dn.toString()));
          const u = d[0];
          let g, f;
          for (var h = 0; h < t.changes.length; h++)
            switch (((g = t.changes[h].modification), t.changes[h].operation)) {
              case 'replace':
                const r = {
                    userpassword: 'password',
                    mail: 'email',
                    cn: ['username'],
                  },
                  o = ['gid', 'uid', '_id', 'userpassword'];
                if (o.indexOf(g.type) > -1)
                  return c(
                    new n.UnwillingToPerformError(
                      `${g.type} is not allowed to modify`
                    )
                  );
                let a = g.type;
                r[g.type] && (a = r[g.type]);
                try {
                  if (
                    ((f =
                      f ||
                      new i({
                        userPoolId: t.currentClientId,
                        secret: s.secret,
                        host: {
                          user: e.authing.graphqlEndPoint.core,
                          oauth: e.authing.graphqlEndPoint.core,
                        },
                        passwordEncPublicKey: e.authing.passwordEncPublicKey,
                      })),
                    a instanceof String || 'string' == typeof a)
                  ) {
                    let e = { _id: u._id };
                    const n = a;
                    (e[n] = g.vals[0]), await f.update(e);
                  } else {
                    let e = { _id: d[0]._id };
                    for (let n = 0; n < a.length; n++) e[a[n]] = g.vals[0];
                    await f.update(e);
                  }
                } catch (e) {
                  return c(new n.UnavailableError(JSON.stringify(e)));
                }
                break;
              case 'add':
              case 'delete':
                return c(new n.UnwillingToPerformError('only replace allowed'));
            }
          return o.end(), c();
        });
    };
  !(function(e) {
    const n = t.collection('userpools');
    n.find({ isDeleted: !1 }).toArray(function(n, t) {
      s.equal(n, null), e(t);
    });
  })(e => {
    for (let n = 0; n < e.length; n++) {
      const t = e[n] || {};
      l(t);
    }
    const n = t.collection('userpools'),
      r = n.watch();
    r.on('change', e => {
      const n = e.operationType;
      if ('insert' === n) {
        const n = e.fullDocument;
        console.log('add client to ldap', n), l(n);
      }
    }),
      o.listen(1389, function() {
        console.log('LDAP server up at: %s', o.url);
      });
  });
};
//# sourceMappingURL=ldap-idp.cjs.production.js.map
