!(function(e) {
  'function' == typeof define && define.amd ? define(e) : e();
})(function() {
  'use strict';
  const e = require('ldapjs'),
    r = require('mongodb').MongoClient,
    n = require('./ldapdb.json'),
    t = require('assert'),
    o = [
      'mongodb://',
      n.user + ':' + n.password + '@',
      n.ip,
      ':',
      n.port,
      '/',
      n.dbname,
    ].join('');
  function c(r, n, t) {
    var o = r instanceof e.SearchRequest;
    return r.connection.ldap.bindDN.equals('cn=root') || o
      ? t()
      : t(new e.InsufficientAccessRightsError());
  }
  r.connect(o, function(e, r) {
    t.equal(null, e), console.log('Connected successfully to server');
    const o = r.db(n.dbname);
    !(function(e, r) {
      const n = e.collection('users');
      n.find({}).toArray(function(e, n) {
        t.equal(e, null), r(n);
      });
    })(o, e => {
      console.log(e);
    }),
      r.close();
  });
  var i = 'o=joyent',
    u = {},
    s = e.createServer();
  s.bind('cn=root', function(r, n, t) {
    return 'cn=root' !== r.dn.toString() || 'secret' !== r.credentials
      ? t(new e.InvalidCredentialsError())
      : (n.end(), t());
  }),
    s.add(i, c, function(r, n, t) {
      var o = r.dn.toString();
      return u[o]
        ? t(new e.EntryAlreadyExistsError(o))
        : ((u[o] = r.toObject().attributes), n.end(), t());
    }),
    s.bind(i, function(r, n, t) {
      var o = r.dn.toString();
      return u[o]
        ? u[o].userpassword
          ? -1 === u[o].userpassword.indexOf(r.credentials)
            ? t(new e.InvalidCredentialsError())
            : (n.end(), t())
          : t(new e.NoSuchAttributeError('userPassword'))
        : t(new e.NoSuchObjectError(o));
    }),
    s.compare(i, c, function(r, n, t) {
      var o = r.dn.toString();
      if (!u[o]) return t(new e.NoSuchObjectError(o));
      if (!u[o][r.attribute]) return t(new e.NoSuchAttributeError(r.attribute));
      for (var c = !1, i = u[o][r.attribute], s = 0; s < i.length; s++)
        if (i[s] === r.value) {
          c = !0;
          break;
        }
      return n.end(c), t();
    }),
    s.del(i, c, function(r, n, t) {
      var o = r.dn.toString();
      return u[o] ? (delete u[o], n.end(), t()) : t(new e.NoSuchObjectError(o));
    }),
    s.modify(i, c, function(r, n, t) {
      const o = r.dn.toString();
      let c = null;
      if (!r.changes.length) return t(new e.ProtocolError('changes required'));
      if (!u[o]) return t(new e.NoSuchObjectError(o));
      for (var i = u[o], s = 0; s < r.changes.length; s++)
        switch (((c = r.changes[s].modification), r.changes[s].operation)) {
          case 'replace':
            if (!i[c.type]) return t(new e.NoSuchAttributeError(c.type));
            c.vals && c.vals.length ? (i[c.type] = c.vals) : delete i[c.type];
            break;
          case 'add':
            i[c.type]
              ? c.vals.forEach(function(e) {
                  -1 === i[c.type].indexOf(e) && i[c.type].push(e);
                })
              : (i[c.type] = c.vals);
            break;
          case 'delete':
            if (!i[c.type]) return t(new e.NoSuchAttributeError(c.type));
            delete i[c.type];
        }
      return n.end(), t();
    }),
    s.search(i, c, function(r, n, t) {
      var o,
        c = r.dn.toString();
      if (!u[c]) return t(new e.NoSuchObjectError(c));
      switch (r.scope) {
        case 'base':
          return (
            r.filter.matches(u[c]) && n.send({ dn: c, attributes: u[c] }),
            n.end(),
            t()
          );
        case 'one':
          o = function(n) {
            if (r.dn.equals(n)) return !0;
            var t = e.parseDN(n).parent();
            return !!t && t.equals(r.dn);
          };
          break;
        case 'sub':
          o = function(e) {
            return r.dn.equals(e) || r.dn.parentOf(e);
          };
      }
      return (
        Object.keys(u).forEach(function(e) {
          o(e) && r.filter.matches(u[e]) && n.send({ dn: e, attributes: u[e] });
        }),
        n.end(),
        t()
      );
    }),
    s.listen(1389, function() {
      console.log('LDAP server up at: %s', s.url);
    });
});
//# sourceMappingURL=ldap-idp.umd.production.js.map
