const ldap = require('ldapjs');
const parseDN = require('ldapjs').parseDN;
const fs = require('fs');
const MongoClient = require('mongodb').MongoClient;
const ObjectId = require('mongodb').ObjectId;
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

  createLDAPServer(db);

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

  // client.close();
});

const createLDAPServer = (db: any) => {
  const server: any = ldap.createServer();

  const findUsers: any = function(callback: any, opts: any) {
    const collection = db.collection('users');
    opts['isDeleted'] = false;
    collection.find(opts).toArray(function(err: any, docs: any) {
      assert.equal(err, null);
      callback(docs);
    });
  };

  const findClients: any = function(callback: any) {
    const clients = db.collection('userclients');
    clients
      .find({
        isDeleted: false,
      })
      .toArray(function(err: any, docs: any) {
        assert.equal(err, null);
        callback(docs);
      });
  };

  findClients((clients: any) => {
    const loadAuthingUsers = (req: any, _res: any, next: any) => {
      let currentClientId: string = '';
      const rdns: any = req.dn.rdns;
      for (let i = 0; i < rdns.length; i++) {
        const rdn = rdns[i];
        for (let key in rdn.attrs) {
          if (key === 'o') {
            currentClientId = rdn.attrs.o.value;
          }
        }
      }

      findUsers(
        (users: any) => {
          req.users = {};
          for (var i = 0; i < users.length; i++) {
            const currentUser: any = users[i];
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
      const SUFFIX: string = `o=${client._id}, ou=users, dc=authing, dc=cn`;

      let bindDN: string = `ou=users,o=${client._id},dc=authing,dc=cn`;

      /*
        DN = uid=LDAP_BINDING_USER（邮箱或者手机号）,ou=Users,o=AUTHING_CLINET_ID,dc=authing,dc=cn
        ldapsearch -H ldap://localhost:1389 -x -D cn=root -LLL -b "o=authingId,ou=users,dc=authing,dc=cn" cn=root
      */

      server.bind(bindDN, function(_req: any, res: any, next: any) {
        // if (req.dn.toString() !== 'cn=root')
        //   return next(new ldap.InvalidCredentialsError());

        res.end();
        return next();
      });

      const authorize = (_req: any, _res: any, next: any) => {
        if (!_req.connection.ldap.bindDN.equals(bindDN))
          return next(new ldap.InsufficientAccessRightsError());
        return next();
      };

      const pre: any = [authorize, loadAuthingUsers];

      server.search(SUFFIX, pre, function(req: any, res: any, next: any) {
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
