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

  const removeUser: any = function(query: any) {
    return new Promise((_resolve: any, _reject: any) => {
      const collection = db.collection('users');
      query['isDeleted'] = false;
      collection.updateOne(query, {
        $set: {
          isDeleted: true,
        },
      });
      findUsers(query)
        .then((users: any) => {
          _resolve(users);
        })
        .catch((err: any) => {
          _reject(err);
        });
    });
  };

  // const updateUser: any = function(query: any, set: any) {
  //   return new Promise((_resolve: any, _reject: any) => {
  //     const collection = db.collection('users');
  //     query['isDeleted'] = false;
  //     collection.updateOne(query, set);
  //     findUsers(query)
  //       .then((users: any) => {
  //         _resolve(users);
  //       })
  //       .catch((err: any) => {
  //         _reject(err);
  //       });
  //   });
  // };

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
        const filterValue: any = req.filter.value || '*';

        const filterKeyMapping: any = {
          cn: 'username',
          gid: '_id',
          uid: '_id',
        };

        let queryOptions: any = {
          registerInClient: ObjectId(req.currentClientId),
        };

        let users: any;
        req.users = {};

        if (filterKeyMapping[filterKey]) {
          const key: any = filterKeyMapping[filterKey];
          queryOptions[key] =
            key === '_id' ? ObjectId(filterValue) : filterValue;
          users = await findUsers(queryOptions);

          const currentUser: any = users[0];
          const cn: any = currentUser.username;
          const dn: string = `cn=${cn},uid=${currentUser._id}, ou=users, o=${
            req.currentClientId
          }, dc=authing, dc=cn`;
          currentUser['cn'] = cn;
          currentUser['gid'] = currentUser._id;
          currentUser['uid'] = currentUser._id;
          currentUser['objectclass'] = 'users';

          delete currentUser['__v'];
          delete currentUser['isDeleted'];
          delete currentUser['salt'];

          res.send({
            dn,
            attributes: currentUser,
          });
        } else {
          users = await findUsers(queryOptions);
          for (var i = 0; i < users.length; i++) {
            const currentUser: any = users[i];
            const cn: any = currentUser.username;
            const dn: string = `cn=${cn},uid=${currentUser._id}, ou=users, o=${
              req.currentClientId
            }, dc=authing, dc=cn`;
            currentUser['cn'] = cn;
            currentUser['gid'] = currentUser._id;
            currentUser['uid'] = currentUser._id;
            currentUser['objectclass'] = 'users';
            delete currentUser['__v'];
            delete currentUser['isDeleted'];
            delete currentUser['salt'];

            req.users[currentUser._id] = {
              dn,
              attributes: currentUser,
            };

            let scopeCheck: any;

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

            Object.keys(req.users).forEach(function(key) {
              if (!scopeCheck(key)) return;

              if (req.filter.matches(req.users[key])) {
                res.send(req.users[key]);
              }
            });

            // console.log(req.users);
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
          username: cn.value,
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
            unionid: `ldap|${cn.value}`,
            registerMethod: 'sso:ldap-add',
          });
        } catch (error) {
          return next(new ldap.UnavailableError(error.toString()));
        }

        res.end();
        return next();
      });

      server.del(SUFFIX, pre, async function(req: any, res: any, next: any) {
        // ldapdelete -H ldap://localhost:1389 -x -D "ou=users,o=5c344f102e450b000170190a,dc=authing,dc=cn" "cn=ldapjs, o=5c344f102e450b000170190a, ou=users, dc=authing,dc=cn"
        const cn = req.dn.rdns[0].attrs.cn;
        if (!req.dn.rdns[0].attrs.cn)
          return next(new ldap.NoSuchObjectError(req.dn.toString()));

        const users = await findUsers({
          registerInClient: ObjectId(req.currentClientId),
          isDeleted: false,
          username: cn.value,
        });

        if (!users || users.length === 0) {
          return next(new ldap.NoSuchObjectError(req.dn.toString()));
        }

        try {
          await removeUser({
            registerInClient: ObjectId(req.currentClientId),
            username: cn.value,
          });
        } catch (error) {
          return next(new ldap.UnavailableError(error.toString()));
        }

        res.end();
        return next();
      });

      server.modify(SUFFIX, pre, async function(req: any, res: any, next: any) {
        // ldapmodify -H ldap://localhost:1389 -x -D "ou=users,o=5c344f102e450b000170190a,dc=authing,dc=cn" -f ./modify.ldif
        const cn: any = req.dn.rdns[0].attrs.cn;
        if (!req.dn.rdns[0].attrs.cn)
          return next(new ldap.NoSuchObjectError(req.dn.toString()));

        if (!req.changes.length)
          return next(new ldap.ProtocolError('changes required'));

        const users: any = await findUsers({
          registerInClient: ObjectId(req.currentClientId),
          isDeleted: false,
          username: cn.value,
        });

        if (!users || users.length === 0) {
          return next(new ldap.NoSuchObjectError(req.dn.toString()));
        }

        const user: any = users[0];

        let mod: any, authing: any;

        for (var i = 0; i < req.changes.length; i++) {
          mod = req.changes[i].modification;
          switch (req.changes[i].operation) {
            case 'replace':
              const typeMapping: any = {
                userpassword: 'password',
                mail: 'email',
                cn: ['username'],
              };

              const notAllowedTypes = ['gid', 'uid', '_id'];

              if (notAllowedTypes.indexOf(mod.type) > -1) {
                return next(
                  new ldap.UnwillingToPerformError(
                    `${mod.type} is not allowed to modify`
                  )
                );
              }

              let fieldModified: any = mod.type;

              if (typeMapping[mod.type]) {
                fieldModified = typeMapping[mod.type];
              }

              try {
                authing =
                  authing ||
                  (await new Authing({
                    clientId: req.currentClientId,
                    secret: '03bb8b2fca823137c7dec63fd0029fc2',
                  }));

                if (
                  fieldModified instanceof String ||
                  typeof fieldModified === 'string'
                ) {
                  let query: any = {
                    _id: user._id,
                  };
                  const field: any = fieldModified;
                  query[field] = mod.vals[0];
                  await authing.update(query);
                } else {
                  let query: any = {
                    _id: users[0]._id,
                  };
                  for (let i = 0; i < fieldModified.length; i++) {
                    query[fieldModified[i]] = mod.vals[0];
                  }
                  await authing.update(query);
                }
              } catch (error) {
                return next(new ldap.UnavailableError(error.toString()));
              }
              break;
            case 'add':
              return next(
                new ldap.UnwillingToPerformError('only replace allowed')
              );
            case 'delete':
              return next(
                new ldap.UnwillingToPerformError('only replace allowed')
              );
          }
        }

        res.end();
        return next();
      });
    }

    server.listen(1389, function() {
      console.log('LDAP server up at: %s', server.url);
    });
  });
};
