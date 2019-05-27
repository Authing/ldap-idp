const ldap = require('ldapjs');
const fs = require('fs');
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
  const db = client.db(ldapdb.dbname);

  const findUsers: any = function(callback: any) {
    const collection = db.collection('users');
    collection.find({}).toArray(function(err: any, docs: any) {
      assert.equal(err, null);
      callback(docs);
    });
  };

  createLDAPServer({
    db,
    findUsers,
  });

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

  client.close();
});

const createLDAPServer = ({ _db: any, findUsers: any }) => {
  const server: any = ldap.createServer();

  function authorize(req: any, _res: any, next: any) {
    if (!req.connection.ldap.bindDN.equals('cn=root'))
      return next(new ldap.InsufficientAccessRightsError());

    return next();
  }

  function loadAuthingUsers(req: any, _res: any, next: any) {
    findUsers((users: any) => {
      req.users = {};

      for (var i = 0; i < users.length; i++) {
        const currentUser: any = users[i];
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

  const SUFFIX: string = 'o=authingId, ou=users, dc=authing, dc=cn';

  /*
    DN = uid=LDAP_BINDING_USER（邮箱或者手机号）,ou=Users,o=AUTHING_CLINET_ID,dc=authing,dc=cn
    ldapsearch -H ldap://localhost:1389 -x -D cn=root -LLL -b "o=authingId,ou=users,dc=authing,dc=cn" cn=root
  */

  server.bind('cn=root', function(req: any, res: any, next: any) {
    console.log(req.dn.rdns);
    // if (req.dn.toString() !== 'cn=root')
    //   return next(new ldap.InvalidCredentialsError());

    res.end();
    return next();
  });

  const pre: any = [authorize, loadAuthingUsers];

  server.search(SUFFIX, pre, function(req: any, res: any, next: any) {
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
