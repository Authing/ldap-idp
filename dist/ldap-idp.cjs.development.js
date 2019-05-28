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
  createLDAPServer(db); // client.close();
});

const createLDAPServer = db => {
  const server = ldap.createServer();

  const findUsers = function(opts) {
    return new Promise((resolve, reject) => {
      const collection = db.collection('users');
      opts['isDeleted'] = false;
      collection.find(opts).toArray(function(err, docs) {
        if (err) reject(err);
        resolve(docs);
      });
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

  const insertUser = function(opts) {
    return new Promise((resolve, reject) => {
      const collection = db.collection('users'); // Insert some documents

      collection.insertMany(opts, (err, result) => {
        if (err) {
          reject(err);
        }

        resolve(result);
      });
    });
  };

  findClients(clients => {
    const loadCurrentClientId = (req, _res, next) => {
      req.currentClientId = '';
      const rdns = req.dn.rdns;

      for (let i = 0; i < rdns.length; i++) {
        const rdn = rdns[i];

        for (let key in rdn.attrs) {
          if (key === 'o') {
            req.currentClientId = rdn.attrs.o.value;
          }
        }
      }

      return next();
    };

    for (let i = 0; i < clients.length; i++) {
      const client = clients[i];
      let bindDN = `ou=users,o=${client._id},dc=authing,dc=cn`;
      const SUFFIX = `o=${client._id}, ou=users, dc=authing, dc=cn`;
      /*
        DN = uid=LDAP_BINDING_USER（邮箱或者手机号）,ou=Users,o=AUTHING_CLINET_ID,dc=authing,dc=cn
        ldapsearch -H ldap://localhost:1389 -x -D "ou=users,o=59f86b4832eb28071bdd9214,dc=authing,dc=cn" -LLL -b "o=59f86b4832eb28071bdd9214,ou=users,dc=authing,dc=cn" cn=18000179176
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

      const pre = [authorize, loadCurrentClientId];
      server.search(SUFFIX, pre, async function(req, res, next) {
        // ldapsearch -H ldap://localhost:1389 -x -D "ou=users,o=5c344f102e450b000170190a,dc=authing,dc=cn" -LLL -b "o=5c344f102e450b000170190a,ou=users,dc=authing,dc=cn" cn=ldap-tester
        const filterKey = req.filter.attribute;
        const filterValue = req.filter.value;
        const filterKeyMapping = {
          cn: ['username', 'email', 'phone', 'unionid'],
          gid: ['_id'],
          uid: ['_id'],
        };
        let queryOptions = {
          registerInClient: ObjectId(req.currentClientId),
        };

        if (filterKeyMapping[filterKey]) {
          const filterMapping = filterKeyMapping[filterKey];

          for (let i = 0; i < filterMapping.length; i++) {
            const key = filterMapping[i];
            queryOptions[key] =
              key === '_id' ? ObjectId(filterValue) : filterValue;
            const users = await findUsers(queryOptions);

            if (users && users.length > 0) {
              const currentUser = users[0];
              const cn =
                currentUser.username ||
                currentUser.email ||
                currentUser.phone ||
                currentUser.unionid;
              const dn = `cn=${cn},uid=${currentUser._id}, ou=users, o=${
                req.currentClientId
              }, dc=authing, dc=cn`;
              currentUser['cn'] = cn;
              currentUser['gid'] = currentUser._id;
              currentUser['uid'] = currentUser._id;
              delete currentUser['__v'];
              delete currentUser['isDeleted'];
              delete currentUser['salt'];
              res.send({
                dn,
                attributes: currentUser,
              });
              break;
            }

            delete queryOptions[key];
          }
        }

        res.end();
        return next();
      });
      server.add(SUFFIX, pre, async function(req, res, next) {
        // ldapadd -H ldap://localhost:1389 -x -D "ou=users,o=5c344f102e450b000170190a,dc=authing,dc=cn" -f ./user.ldif
        const cn = req.dn.rdns[0].cn;
        console.log(cn, req.dn.rdns[0]);
        if (!req.dn.rdns[0].cn)
          return next(new ldap.ConstraintViolationError('cn required')); // return next(new ldap.EntryAlreadyExistsError(req.dn.toString()));

        await insertUser({
          username: cn,
          nickname: cn,
          unionid: cn,
          isDeleted: false,
          isBlocked: false,
          createdAt: Date.now,
          updatedAt: Date.now,
          photo: 'https://usercontents.authing.cn/authing-avatar.png',
          registerInClient: req.currentClientId,
          registerMethod: 'sso:ldap-add',
        });
        res.end();
        return next();
      });
      server.del(SUFFIX, pre, async function(req, res, next) {
        // ldapdelete -H ldap://localhost:1389 -x -D "ou=users,o=5c344f102e450b000170190a,dc=authing,dc=cn" "o=5c344f102e450b000170190a,ou=users,dc=authing,dc=cn"
        console.log(req.dn.rdns[0].cn);

        if (!req.dn.rdns[0].cn) {
          return next(new ldap.NoSuchObjectError(req.dn.toString()));
        } // const user = await findUsers({
        // });
        // !req.users[req.dn.rdns[0].cn]
        // return next(new ldap.OperationsError(msg));

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
