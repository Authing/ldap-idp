!(function(e) {
  'function' == typeof define && define.amd ? define(e) : e();
})(function() {
  'use strict';
  const e = require('ldapjs'),
    n = require('mongodb').MongoClient,
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
  n.connect(c, function(e, n) {
    i.equal(null, e), console.log('Connected successfully to server');
    const t = n.db(r.dbname);
    s(t);
  });
  const s = n => {
    const r = e.createServer(),
      c = function(e) {
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
      const s = (e, n, t) => {
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
        const a = i[d];
        let l = `ou=users,o=${a._id},dc=authing,dc=cn`;
        const u = `o=${a._id}, ou=users, dc=authing, dc=cn`;
        r.bind(l, function(e, n, t) {
          return n.end(), t();
        });
        const f = (n, t, r) =>
            n.connection.ldap.bindDN.equals(l)
              ? r()
              : r(new e.InsufficientAccessRightsError()),
          g = [f, s];
        r.search(u, g, async function(e, n, r) {
          const i = e.filter.attribute,
            o = e.filter.value,
            s = { cn: ['username', 'unionid'], gid: ['_id'], uid: ['_id'] };
          let d = { registerInClient: t(e.currentClientId) };
          if (s[i]) {
            const r = s[i];
            for (let i = 0; i < r.length; i++) {
              const s = r[i];
              d[s] = '_id' === s ? t(o) : o;
              const a = await c(d);
              if (a && a.length > 0) {
                const t = a[0],
                  r = t.username || t.unionid,
                  i = `cn=${r},uid=${t._id}, ou=users, o=${
                    e.currentClientId
                  }, dc=authing, dc=cn`;
                (t.cn = r),
                  (t.gid = t._id),
                  (t.uid = t._id),
                  delete t.__v,
                  delete t.isDeleted,
                  delete t.salt,
                  n.send({ dn: i, attributes: t });
                break;
              }
              delete d[s];
            }
          }
          return n.end(), r();
        }),
          r.add(u, g, async function(n, r, i) {
            const s = n.dn.rdns[0].attrs.cn;
            if (!n.dn.rdns[0].attrs.cn)
              return i(new e.ConstraintViolationError('cn required'));
            const d = await c({
              registerInClient: t(n.currentClientId),
              isDeleted: !1,
              username: s.value,
            });
            if (d && d.length > 0)
              return i(new e.EntryAlreadyExistsError(n.dn.toString()));
            try {
              const t = await new o({
                clientId: n.currentClientId,
                secret: '03bb8b2fca823137c7dec63fd0029fc2',
              });
              await t.register({
                username: s.value,
                nickname: s.value,
                unionid: `ldap|${s.value}`,
                registerMethod: 'sso:ldap-add',
              });
            } catch (n) {
              return i(new e.UnavailableError(n.toString()));
            }
            return r.end(), i();
          }),
          r.del(u, g, async function(r, i, o) {
            const s = r.dn.rdns[0].attrs.cn;
            if (!r.dn.rdns[0].attrs.cn)
              return o(new e.NoSuchObjectError(r.dn.toString()));
            const d = await c({
              registerInClient: t(r.currentClientId),
              isDeleted: !1,
              username: s.value,
            });
            if (!d || 0 === d.length)
              return o(new e.NoSuchObjectError(r.dn.toString()));
            try {
              await ((a = {
                registerInClient: t(r.currentClientId),
                username: s.value,
              }),
              new Promise((e, t) => {
                const r = n.collection('users');
                (a.isDeleted = !1),
                  r.updateOne(a, { $set: { isDeleted: !0 } }),
                  c(a)
                    .then(n => {
                      e(n);
                    })
                    .catch(e => {
                      t(e);
                    });
              }));
            } catch (n) {
              return o(new e.UnavailableError(n.toString()));
            }
            var a;
            return i.end(), o();
          }),
          r.modify(u, g, async function(n, r, i) {
            const s = n.dn.rdns[0].attrs.cn;
            if (!n.dn.rdns[0].attrs.cn)
              return i(new e.NoSuchObjectError(n.dn.toString()));
            if (!n.changes.length)
              return i(new e.ProtocolError('changes required'));
            const d = await c({
              registerInClient: t(n.currentClientId),
              isDeleted: !1,
              username: s.value,
            });
            if (!d || 0 === d.length)
              return i(new e.NoSuchObjectError(n.dn.toString()));
            const a = d[0];
            let l, u;
            for (var f = 0; f < n.changes.length; f++)
              switch (
                ((l = n.changes[f].modification), n.changes[f].operation)
              ) {
                case 'replace':
                  const t = {
                      userpassword: 'password',
                      mail: 'email',
                      cn: ['username'],
                    },
                    r = ['gid', 'uid', '_id'];
                  if (r.indexOf(l.type) > -1)
                    return i(
                      new e.UnwillingToPerformError(
                        `${l.type} is not allowed to modify`
                      )
                    );
                  let c = l.type;
                  t[l.type] && (c = t[l.type]);
                  try {
                    if (
                      ((u =
                        u ||
                        (await new o({
                          clientId: n.currentClientId,
                          secret: '03bb8b2fca823137c7dec63fd0029fc2',
                        }))),
                      c instanceof String || 'string' == typeof c)
                    ) {
                      let e = { _id: a._id };
                      const n = c;
                      (e[n] = l.vals[0]), await u.update(e);
                    } else {
                      let e = { _id: d[0]._id };
                      for (let n = 0; n < c.length; n++) e[c[n]] = l.vals[0];
                      await u.update(e);
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
