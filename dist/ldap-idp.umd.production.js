!(function(n) {
  'function' == typeof define && define.amd ? define(n) : n();
})(function() {
  'use strict';
  const n = require('ldapjs'),
    e = require('mongodb').MongoClient,
    t = require('mongodb').ObjectId,
    o = require('./ldapdb.json'),
    i = require('assert'),
    r = [
      'mongodb://',
      o.user + ':' + o.password + '@',
      o.ip,
      ':',
      o.port,
      '/',
      o.dbname,
    ].join('');
  e.connect(r, function(n, e) {
    i.equal(null, n), console.log('Connected successfully to server');
    const t = e.db(o.dbname);
    c(t);
  });
  const c = e => {
    const o = n.createServer(),
      r = function(n) {
        return new Promise((t, o) => {
          const i = e.collection('users');
          (n.isDeleted = !1),
            i.find(n).toArray(function(n, e) {
              n && o(n), t(e);
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
        const o = n.dn.rdns;
        for (let e = 0; e < o.length; e++) {
          const t = o[e];
          for (let e in t.attrs)
            'o' === e && (n.currentClientId = t.attrs.o.value);
        }
        return t();
      };
      for (let c = 0; c < e.length; c++) {
        const s = e[c],
          u = `o=${s._id}, ou=users, dc=authing, dc=cn`;
        let d = `ou=users,o=${s._id},dc=authing,dc=cn`;
        o.bind(d, function(n, e, t) {
          return e.end(), t();
        });
        const l = (e, t, o) =>
            e.connection.ldap.bindDN.equals(d)
              ? o()
              : o(new n.InsufficientAccessRightsError()),
          a = [l, i];
        o.search(u, a, async function(n, e, o) {
          const i = n.filter.attribute,
            c = n.filter.value,
            s = {
              cn: ['username', 'email', 'phone', 'unionid'],
              gid: ['_id'],
              uid: ['_id'],
            };
          let u = { registerInClient: t(n.currentClientId) };
          if (s[i]) {
            const o = s[i];
            for (let i = 0; i < o.length; i++) {
              const s = o[i];
              u[s] = '_id' === s ? t(c) : c;
              const d = await r(u);
              if (d && d.length > 0) {
                const t = d[0],
                  o = t.username || t.email || t.phone || t.unionid,
                  i = `cn=${o},uid=${t._id}, ou=users, o=${
                    n.currentClientId
                  }, dc=authing, dc=cn`;
                (t.cn = o),
                  (t.gid = t._id),
                  (t.uid = t._id),
                  delete t.__v,
                  e.send({ dn: i, attributes: t });
                break;
              }
              delete u[s];
            }
          }
          return e.end(), o();
        });
      }
      o.listen(1389, function() {
        console.log('LDAP server up at: %s', o.url);
      });
    });
  };
});
//# sourceMappingURL=ldap-idp.umd.production.js.map
