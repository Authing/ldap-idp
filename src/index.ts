const ldap = require('ldapjs');
const MongoClient = require('mongodb').MongoClient;
const ldapdb = require('./ldapdb.json');

const assert = require('assert');

// Connection URL
const url = [
  'mongodb://',
  ldapdb.user + ':' + ldapdb.password + '@',
  ldapdb.ip,
  ':',
  ldapdb.port,
  '/',
  ldapdb.dbname,
].join('');

// Use connect method to connect to the server
MongoClient.connect(url, function(_err: any, client: any) {
  assert.equal(null, _err);
  console.log('Connected successfully to server');

  // const insertDocuments = function(db, callback) {
  //   // Get the documents collection
  //   const collection = db.collection('documents');
  //   // Insert some documents
  //   collection.insertMany([
  //     {a : 1}, {a : 2}, {a : 3}
  //   ], function(err, result) {
  //     assert.equal(err, null);
  //     assert.equal(3, result.result.n);
  //     assert.equal(3, result.ops.length);
  //     console.log("Inserted 3 documents into the collection");
  //     callback(result);
  //   });
  // }

  const findDocuments = function(db: any, callback: any) {
    const collection = db.collection('users');
    collection.find({}).toArray(function(err: any, docs: any) {
      assert.equal(err, null);
      callback(docs);
    });
  };

  const db = client.db(ldapdb.dbname);

  findDocuments(db, (users: any) => {
    console.log(users);
  });

  client.close();
});

///--- Shared handlers

function authorize(
  req: {
    connection: { ldap: { bindDN: { equals: (arg0: string) => string } } };
  },
  _res: any,
  next: { (arg0: any): void; (): void }
) {
  /* Any user may search after bind, only cn=root has full power */
  var isSearch = req instanceof ldap.SearchRequest;
  if (!req.connection.ldap.bindDN.equals('cn=root') && !isSearch)
    return next(new ldap.InsufficientAccessRightsError());

  return next();
}

///--- Globals

var SUFFIX: string = 'o=joyent';
var db: any = {};
var server: any = ldap.createServer();

server.bind('cn=root', function(req: any, res: any, next: any) {
  if (req.dn.toString() !== 'cn=root' || req.credentials !== 'secret')
    return next(new ldap.InvalidCredentialsError());

  res.end();
  return next();
});

server.add(SUFFIX, authorize, function(
  req: { dn: { toString: () => string }; toObject: () => { attributes: any } },
  res: { end: () => void },
  next: { (arg0: any): void; (): void }
) {
  var dn = req.dn.toString();

  if (db[dn]) return next(new ldap.EntryAlreadyExistsError(dn));

  db[dn] = req.toObject().attributes;
  res.end();
  return next();
});

server.bind(SUFFIX, function(
  req: { dn: { toString: () => string }; credentials: any },
  res: { end: () => void },
  next: { (arg0: any): void; (arg0: any): void; (arg0: any): void; (): void }
) {
  var dn = req.dn.toString();
  if (!db[dn]) return next(new ldap.NoSuchObjectError(dn));

  if (!db[dn].userpassword)
    return next(new ldap.NoSuchAttributeError('userPassword'));

  if (db[dn].userpassword.indexOf(req.credentials) === -1)
    return next(new ldap.InvalidCredentialsError());

  res.end();
  return next();
});

server.compare(SUFFIX, authorize, function(
  req: {
    dn: { toString: () => string };
    attribute: string | number;
    value: any;
  },
  res: { end: (arg0: boolean) => void },
  next: { (arg0: any): void; (arg0: any): void; (): void }
) {
  var dn = req.dn.toString();
  if (!db[dn]) return next(new ldap.NoSuchObjectError(dn));

  if (!db[dn][req.attribute])
    return next(new ldap.NoSuchAttributeError(req.attribute));

  var matches = false;
  var vals = db[dn][req.attribute];
  for (var i = 0; i < vals.length; i++) {
    if (vals[i] === req.value) {
      matches = true;
      break;
    }
  }

  res.end(matches);
  return next();
});

server.del(SUFFIX, authorize, function(
  req: { dn: { toString: () => string } },
  res: { end: () => void },
  next: { (arg0: any): void; (): void }
) {
  var dn = req.dn.toString();
  if (!db[dn]) return next(new ldap.NoSuchObjectError(dn));

  delete db[dn];

  res.end();
  return next();
});

server.modify(SUFFIX, authorize, function(
  req: {
    dn: { toString: () => string };
    changes: { operation: any; modification: any }[];
  },
  res: { end: () => void },
  next: {
    (arg0: any): void;
    (arg0: any): void;
    (arg0: any): void;
    (arg0: any): void;
    (): void;
  }
) {
  const dn = req.dn.toString();
  let mod: any = null;
  if (!req.changes.length)
    return next(new ldap.ProtocolError('changes required'));
  if (!db[dn]) return next(new ldap.NoSuchObjectError(dn));

  var entry = db[dn];

  for (var i = 0; i < req.changes.length; i++) {
    mod = req.changes[i].modification;
    switch (req.changes[i].operation) {
      case 'replace':
        if (!entry[mod.type])
          return next(new ldap.NoSuchAttributeError(mod.type));

        if (!mod.vals || !mod.vals.length) {
          delete entry[mod.type];
        } else {
          entry[mod.type] = mod.vals;
        }

        break;

      case 'add':
        if (!entry[mod.type]) {
          entry[mod.type] = mod.vals;
        } else {
          mod.vals.forEach(function(v: any) {
            if (entry[mod.type].indexOf(v) === -1) entry[mod.type].push(v);
          });
        }

        break;

      case 'delete':
        if (!entry[mod.type])
          return next(new ldap.NoSuchAttributeError(mod.type));

        delete entry[mod.type];

        break;
    }
  }

  res.end();
  return next();
});

server.search(SUFFIX, authorize, function(
  req: {
    dn: {
      toString: () => string;
      equals: { (arg0: any): boolean; (arg0: any): boolean };
      parentOf: (arg0: any) => void;
    };
    scope: any;
    filter: { matches: { (arg0: any): boolean; (arg0: any): boolean } };
  },
  res: {
    send: {
      (arg0: { dn: any; attributes: any }): void;
      (arg0: { dn: string; attributes: any }): void;
    };
    end: { (): void; (): void };
  },
  next: { (arg0: any): void; (): void; (): void }
) {
  var dn = req.dn.toString();
  if (!db[dn]) return next(new ldap.NoSuchObjectError(dn));

  var scopeCheck: { (k: any): any; (k: any): any; (arg0: string): void };

  switch (req.scope) {
    case 'base':
      if (req.filter.matches(db[dn])) {
        res.send({
          dn: dn,
          attributes: db[dn],
        });
      }

      res.end();
      return next();

    case 'one':
      scopeCheck = function(k: any) {
        if (req.dn.equals(k)) return true;

        var parent = ldap.parseDN(k).parent();
        return parent ? parent.equals(req.dn) : false;
      };
      break;

    case 'sub':
      scopeCheck = function(k: any) {
        return req.dn.equals(k) || req.dn.parentOf(k);
      };

      break;
  }

  Object.keys(db).forEach(function(key) {
    if (!scopeCheck(key)) return;

    if (req.filter.matches(db[key])) {
      res.send({
        dn: key,
        attributes: db[key],
      });
    }
  });

  res.end();
  return next();
});

///--- Fire it up

server.listen(1389, function() {
  console.log('LDAP server up at: %s', server.url);
});
