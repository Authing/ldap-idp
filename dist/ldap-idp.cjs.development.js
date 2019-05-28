'use strict';

const ldap =
  /*#__PURE__*/
  require('ldapjs');

const parseDN =
  /*#__PURE__*/
  require('ldapjs').parseDN;

const MongoClient =
  /*#__PURE__*/
  require('mongodb').MongoClient;

const ObjectId =
  /*#__PURE__*/
  require('mongodb').ObjectId;

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

  const findUsers = function(callback, opts) {
    const collection = db.collection('users');
    opts['isDeleted'] = false;
    collection.find(opts).toArray(function(err, docs) {
      assert.equal(err, null);
      callback(docs);
    });
  };

  const findClients = function(callback) {
    const clients = db.collection('userclients');
    clients
      .find({
        isDeleted: false,
      })
      .toArray(function(err, docs) {
        assert.equal(err, null);
        callback(docs);
      });
  };

  findClients(clients => {
    const loadAuthingUsers = (req, _res, next) => {
      let currentClientId = '';
      const rdns = req.dn.rdns;

      for (let i = 0; i < rdns.length; i++) {
        const rdn = rdns[i];

        for (let key in rdn.attrs) {
          if (key === 'o') {
            currentClientId = rdn.attrs.o.value;
          }
        }
      }

      findUsers(
        users => {
          req.users = {};

          for (var i = 0; i < users.length; i++) {
            const currentUser = users[i];
            req.users[currentUser._id] = {
              dn: `cn=${currentUser.username ||
                currentUser.email ||
                currentUser.phone ||
                currentUser.unionid},uid=${
                currentUser._id
              }, ou=users, o=${currentClientId}, dc=authing, dc=cn`,
              attributes: {
                cn:
                  currentUser.username ||
                  currentUser.email ||
                  currentUser.phone ||
                  currentUser.unionid,
                uid: currentUser._id,
                gid: currentUser._id,
                unionid: currentUser.unionid,
                email: currentUser.email,
                phone: currentUser.phone,
                nickname: currentUser.nickname,
                username: currentUser.username,
                photo: currentUser.photo,
                emailVerified: currentUser.emailVerified,
                oauth: currentUser.oauth,
                token: currentUser.token,
                registerInClient: currentUser.registerInClient,
                loginsCount: currentUser.loginsCount,
                lastIP: currentUser.lastIP,
                company: currentUser.company,
                objectclass: 'authingUser',
              },
            };
          }

          return next();
        },
        {
          registerInClient: ObjectId(currentClientId),
        }
      );
    };

    for (let i = 0; i < clients.length; i++) {
      const client = clients[i];
      const SUFFIX = `o=${client._id}, ou=users, dc=authing, dc=cn`;
      let bindDN = `ou=users,o=${client._id},dc=authing,dc=cn`;
      /*
        DN = uid=LDAP_BINDING_USER（邮箱或者手机号）,ou=Users,o=AUTHING_CLINET_ID,dc=authing,dc=cn
        ldapsearch -H ldap://localhost:1389 -x -D cn=root -LLL -b "o=authingId,ou=users,dc=authing,dc=cn" cn=root
      */

      server.bind(bindDN, function(_req, res, next) {
        // if (req.dn.toString() !== 'cn=root')
        //   return next(new ldap.InvalidCredentialsError());
        res.end();
        return next();
      });

      const authorize = (_req, _res, next) => {
        if (!_req.connection.ldap.bindDN.equals(bindDN))
          return next(new ldap.InsufficientAccessRightsError());
        return next();
      };

      const pre = [authorize, loadAuthingUsers];
      server.search(SUFFIX, pre, function(req, res, next) {
        Object.keys(req.users).forEach(function(k) {
          if (req.filter.matches(req.users[k].attributes))
            res.send(req.users[k]);
        });
        res.end();
        return next();
      });
    }

    server.listen(1389, function() {
      console.log('LDAP server up at: %s', server.url);
    });
  });
};
//# sourceMappingURL=ldap-idp.cjs.development.js.map
