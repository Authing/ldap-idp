(function(factory) {
  typeof define === 'function' && define.amd ? define(factory) : factory();
})(function() {
  'use strict';

  const ldap =
    /*#__PURE__*/
    require('ldapjs');

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
    createLDAPServer(db); // const insertDocuments = function(db, callback) {
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
    // client.close();
  });

  const createLDAPServer = db => {
    const server = ldap.createServer();

    const findUsers = function(callback) {
      const collection = db.collection('users');
      collection.find({}).toArray(function(err, docs) {
        assert.equal(err, null);
        callback(docs);
      });
    };

    function authorize(req, _res, next) {
      if (!req.connection.ldap.bindDN.equals('cn=root'))
        return next(new ldap.InsufficientAccessRightsError());
      return next();
    }

    function loadAuthingUsers(req, _res, next) {
      findUsers(users => {
        req.users = {};

        for (var i = 0; i < users.length; i++) {
          const currentUser = users[i];
          req.users[currentUser._id] = {
            dn: `cn=${currentUser.username ||
              currentUser.email ||
              currentUser.phone ||
              currentUser.unionid},uid=${
              currentUser._id
            }, ou=users, o=authingId, dc=authing, dc=cn`,
            attributes: {
              cn:
                currentUser.username ||
                currentUser.email ||
                currentUser.phone ||
                currentUser.unionid,
              uid: currentUser._id,
              gid: currentUser._id,
              username: currentUser.username,
              objectclass: 'authingUser',
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
    const pre = [authorize, loadAuthingUsers];
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
