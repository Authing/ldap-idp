const ldap = require('ldapjs');
const parseDN = require('ldapjs').parseDN;
const fs = require('fs');
const MongoClient = require('mongodb').MongoClient;
const ObjectId = require('mongodb').ObjectId;
const ldapdb = require('./ldapdb.json');

const assert = require('assert');

const Authing = require('authing-js-sdk');

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
  // client.close();
});

const createLDAPServer = (db: any) => {
  const server: any = ldap.createServer();

  const findUsers: any = function(opts: any) {
    return new Promise((resolve: any, reject: any) => {
      const collection = db.collection('users');
      opts['isDeleted'] = false;
      collection.find(opts).toArray(function(err: any, docs: any) {
        if (err) reject(err);
        resolve(docs);
      });
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
    const loadCurrentClientId = (req: any, _res: any, next: any) => {
      req.currentClientId = '';
      const rdns: any = req.dn.rdns;
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

      let bindDN: string = `ou=users,o=${client._id},dc=authing,dc=cn`;
      const SUFFIX: string = `o=${client._id}, ou=users, dc=authing, dc=cn`;

      /*
        DN = uid=LDAP_BINDING_USER（邮箱或者手机号）,ou=Users,o=AUTHING_CLINET_ID,dc=authing,dc=cn
        ldapsearch -H ldap://localhost:1389 -x -D "ou=users,o=59f86b4832eb28071bdd9214,dc=authing,dc=cn" -LLL -b "o=59f86b4832eb28071bdd9214,ou=users,dc=authing,dc=cn" cn=18000179176
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

      const pre: any = [authorize, loadCurrentClientId];

      server.search(SUFFIX, pre, async function(req: any, res: any, next: any) {
        // ldapsearch -H ldap://localhost:1389 -x -D "ou=users,o=5c344f102e450b000170190a,dc=authing,dc=cn" -LLL -b "o=5c344f102e450b000170190a,ou=users,dc=authing,dc=cn" cn=ldap-tester

        const filterKey: any = req.filter.attribute;
        const filterValue: any = req.filter.value;

        const filterKeyMapping: any = {
          cn: ['username', 'email', 'phone', 'unionid'],
          gid: ['_id'],
          uid: ['_id'],
        };

        let queryOptions: any = {
          registerInClient: ObjectId(req.currentClientId),
        };

        if (filterKeyMapping[filterKey]) {
          const filterMapping: any = filterKeyMapping[filterKey];
          for (let i = 0; i < filterMapping.length; i++) {
            const key: string = filterMapping[i];
            queryOptions[key] =
              key === '_id' ? ObjectId(filterValue) : filterValue;

            const users: object[] = await findUsers(queryOptions);

            if (users && users.length > 0) {
              const currentUser: any = users[0];
              const cn: any =
                currentUser.username ||
                currentUser.email ||
                currentUser.phone ||
                currentUser.unionid;
              const dn: string = `cn=${cn},uid=${
                currentUser._id
              }, ou=users, o=${req.currentClientId}, dc=authing, dc=cn`;
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

      server.add(SUFFIX, pre, async function(req: any, res: any, next: any) {
        // ldapadd -H ldap://localhost:1389 -x -D "ou=users,o=5c344f102e450b000170190a,dc=authing,dc=cn" -f ./user.ldif
        const cn = req.dn.rdns[0].attrs.cn;
        if (!req.dn.rdns[0].attrs.cn)
          return next(new ldap.ConstraintViolationError('cn required'));

        const users = await findUsers({
          registerInClient: ObjectId(req.currentClientId),
          isDeleted: false,
          unionid: cn.value,
        });

        if (users && users.length > 0) {
          return next(new ldap.EntryAlreadyExistsError(req.dn.toString()));
        }

        try {
          const authing = await new Authing({
            clientId: req.currentClientId,
            secret: '03bb8b2fca823137c7dec63fd0029fc2',
          });

          await authing.register({
            username: cn.value,
            nickname: cn.value,
            unionid: cn.value,
            registerMethod: 'sso:ldap-add',
          });
        } catch (error) {
          return next(new ldap.UnavailableError(error.toString()));
        }

        res.end();
        return next();
      });

      server.del(SUFFIX, pre, async function(req: any, res: any, next: any) {
        // ldapdelete -H ldap://localhost:1389 -x -D "ou=users,o=5c344f102e450b000170190a,dc=authing,dc=cn" "o=5c344f102e450b000170190a,ou=users,dc=authing,dc=cn"
        console.log(req.dn.rdns[0].cn);
        if (!req.dn.rdns[0].cn) {
          return next(new ldap.NoSuchObjectError(req.dn.toString()));
        }

        // const user = await findUsers({

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
