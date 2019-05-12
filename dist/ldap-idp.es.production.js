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
var s = 'o=joyent',
  u = {},
  a = e.createServer();
a.bind('cn=root', function(r, n, t) {
  return 'cn=root' !== r.dn.toString() || 'secret' !== r.credentials
    ? t(new e.InvalidCredentialsError())
    : (n.end(), t());
}),
  a.add(s, c, function(r, n, t) {
    var o = r.dn.toString();
    return u[o]
      ? t(new e.EntryAlreadyExistsError(o))
      : ((u[o] = r.toObject().attributes), n.end(), t());
  }),
  a.bind(s, function(r, n, t) {
    var o = r.dn.toString();
    return u[o]
      ? u[o].userpassword
        ? -1 === u[o].userpassword.indexOf(r.credentials)
          ? t(new e.InvalidCredentialsError())
          : (n.end(), t())
        : t(new e.NoSuchAttributeError('userPassword'))
      : t(new e.NoSuchObjectError(o));
  }),
  a.compare(s, c, function(r, n, t) {
    var o = r.dn.toString();
    if (!u[o]) return t(new e.NoSuchObjectError(o));
    if (!u[o][r.attribute]) return t(new e.NoSuchAttributeError(r.attribute));
    for (var c = !1, s = u[o][r.attribute], a = 0; a < s.length; a++)
      if (s[a] === r.value) {
        c = !0;
        break;
      }
    return n.end(c), t();
  }),
  a.del(s, c, function(r, n, t) {
    var o = r.dn.toString();
    return u[o] ? (delete u[o], n.end(), t()) : t(new e.NoSuchObjectError(o));
  }),
  a.modify(s, c, function(r, n, t) {
    const o = r.dn.toString();
    let c = null;
    if (!r.changes.length) return t(new e.ProtocolError('changes required'));
    if (!u[o]) return t(new e.NoSuchObjectError(o));
    for (var s = u[o], a = 0; a < r.changes.length; a++)
      switch (((c = r.changes[a].modification), r.changes[a].operation)) {
        case 'replace':
          if (!s[c.type]) return t(new e.NoSuchAttributeError(c.type));
          c.vals && c.vals.length ? (s[c.type] = c.vals) : delete s[c.type];
          break;
        case 'add':
          s[c.type]
            ? c.vals.forEach(function(e) {
                -1 === s[c.type].indexOf(e) && s[c.type].push(e);
              })
            : (s[c.type] = c.vals);
          break;
        case 'delete':
          if (!s[c.type]) return t(new e.NoSuchAttributeError(c.type));
          delete s[c.type];
      }
    return n.end(), t();
  }),
  a.search(s, c, function(r, n, t) {
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
  a.listen(1389, function() {
    console.log('LDAP server up at: %s', a.url);
  });
//# sourceMappingURL=ldap-idp.es.production.js.map
