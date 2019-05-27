(function(factory) {
  typeof define === 'function' && define.amd ? define(factory) : factory();
})(function() {
  'use strict';

  const ldap =
    /*#__PURE__*/
    require('ldapjs');

  const fs =
    /*#__PURE__*/
    require('fs');

  const MongoClient =
    /*#__PURE__*/
    require('mongodb').MongoClient;

  const ldapdb =
    /*#__PURE__*/
    require('./ldapdb.json');

  const assert =
    /*#__PURE__*/
    require('assert'); // Connection URL

  const url =
    /*#__PURE__*/
    [
      'mongodb://',
      ldapdb.user + ':' + ldapdb.password + '@',
      ldapdb.ip,
      ':',
      ldapdb.port,
      '/',
      ldapdb.dbname,
    ].join(''); // Use connect method to connect to the server

  MongoClient.connect(url, function(_err, client) {
    assert.equal(null, _err);
    console.log('Connected successfully to server');
    const db = client.db(ldapdb.dbname);
    createLDAPServer(); // const insertDocuments = function(db, callback) {
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

    const findDocuments = function(db, callback) {
      const collection = db.collection('users');
      collection.find({}).toArray(function(err, docs) {
        assert.equal(err, null);
        callback(docs);
      });
    };

    findDocuments(db, users => {
      console.log(users);
    });
    client.close();
  });

  const createLDAPServer = () => {
    const server = ldap.createServer();

    function authorize(req, _res, next) {
      if (!req.connection.ldap.bindDN.equals('cn=root'))
        return next(new ldap.InsufficientAccessRightsError());
      return next();
    }

    function loadPasswdFile(req, _res, next) {
      fs.readFile('/etc/passwd', 'utf8', function(err, data) {
        if (err) return next(new ldap.OperationsError(err.message));
        req.users = {};
        var lines = data.split('\n');

        for (var i = 0; i < lines.length; i++) {
          if (!lines[i] || /^#/.test(lines[i])) continue;
          var record = lines[i].split(':');
          if (!record || !record.length) continue;
          req.users[record[0]] = {
            dn: `cn=${record[0]},uid=${
              record[2]
            }, ou=users, o=authingId, dc=authing, dc=cn`,
            attributes: {
              cn: record[0],
              uid: record[2],
              gid: record[3],
              description: record[4],
              homedirectory: record[5],
              shell: record[6] || '',
              objectclass: 'unixUser',
            },
          };
        }

        return next();
      });
    }

    const SUFFIX = 'o=authingId, ou=users, dc=authing, dc=cn';
    /*
      DN = uid=LDAP_BINDING_USER（邮箱或者手机号）,ou=Users,o=AUTHING_CLINET_ID,dc=authing,dc=cn
      ldapsearch -H ldap://localhost:1389 -x -D cn=root -LLL -b "o=authingId,ou=users,dc=authing,dc=cn" cn=root
    */

    server.bind('cn=root', function(req, res, next) {
      console.log(req.dn.rdns); // if (req.dn.toString() !== 'cn=root')
      //   return next(new ldap.InvalidCredentialsError());

      res.end();
      return next();
    });
    const pre = [authorize, loadPasswdFile];
    server.search(SUFFIX, pre, function(req, res, next) {
      Object.keys(req.users).forEach(function(k) {
        if (req.filter.matches(req.users[k].attributes)) res.send(req.users[k]);
      });
      res.end();
      return next();
    });
    server.listen(1389, function() {
      console.log('LDAP server up at: %s', server.url);
    });
  };
});
//# sourceMappingURL=ldap-idp.umd.development.js.map
