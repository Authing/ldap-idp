(function(factory) {
  typeof define === 'function' && define.amd ? define(factory) : factory();
})(function() {
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
    require('assert');

  const Authing =
    /*#__PURE__*/
    require('authing-js-sdk'); // Connection URL

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

    const removeUser = function(query) {
      return new Promise((_resolve, _reject) => {
        const collection = db.collection('users');
        query['isDeleted'] = false;
        collection.updateOne(query, {
          $set: {
            isDeleted: true,
          },
        });
        findUsers(query)
          .then(users => {
            _resolve(users);
          })
          .catch(err => {
            _reject(err);
          });
      });
    }; // const updateUser: any = function(query: any, set: any) {
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

        server.bind(bindDN, async function(_req, res, next) {
          const o = _req.dn.rdns[1].attrs;
          let currentClientId;

          if (o['o']) {
            currentClientId = o.o.value;
          }

          if (
            !(
              currentClientId.toString() === client._id.toString() &&
              _req.credentials.toString() === client.secret.toString()
            )
          )
            return next(new ldap.InvalidCredentialsError());
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
          const filterValue = req.filter.value || '*';
          const filterKeyMapping = {
            cn: 'username',
            gid: '_id',
            uid: '_id',
          };
          let queryOptions = {
            registerInClient: ObjectId(req.currentClientId),
          };
          let users;
          req.users = {};

          if (filterKeyMapping[filterKey]) {
            const key = filterKeyMapping[filterKey];
            queryOptions[key] =
              key === '_id' ? ObjectId(filterValue) : filterValue;
            users = await findUsers(queryOptions);
            const currentUser = users[0];
            const cn = currentUser.username;
            const dn = `cn=${cn},uid=${currentUser._id}, ou=users, o=${
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
              const currentUser = users[i];
              const cn = currentUser.username;
              const dn = `cn=${cn},uid=${currentUser._id}, ou=users, o=${
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
              let scopeCheck;

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
                  scopeCheck = function(k) {
                    if (req.dn.equals(k)) return true;
                    var parent = ldap.parseDN(k).parent();
                    return parent ? parent.equals(req.dn) : false;
                  };

                  break;

                case 'sub':
                  scopeCheck = function(k) {
                    return req.dn.equals(k) || req.dn.parentOf(k);
                  };

                  break;
              }

              Object.keys(req.users).forEach(function(key) {
                if (!scopeCheck(key)) return;

                if (req.filter.matches(req.users[key])) {
                  res.send(req.users[key]);
                }
              }); // console.log(req.users);
            }
          }

          res.end();
          return next();
        });
        server.add(SUFFIX, pre, async function(req, res, next) {
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
              secret: client.secret,
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
        server.del(SUFFIX, pre, async function(req, res, next) {
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
        server.modify(SUFFIX, pre, async function(req, res, next) {
          // ldapmodify -H ldap://localhost:1389 -x -D "ou=users,o=5c344f102e450b000170190a,dc=authing,dc=cn" -f ./modify.ldif
          const cn = req.dn.rdns[0].attrs.cn;
          if (!req.dn.rdns[0].attrs.cn)
            return next(new ldap.NoSuchObjectError(req.dn.toString()));
          if (!req.changes.length)
            return next(new ldap.ProtocolError('changes required'));
          const users = await findUsers({
            registerInClient: ObjectId(req.currentClientId),
            isDeleted: false,
            username: cn.value,
          });

          if (!users || users.length === 0) {
            return next(new ldap.NoSuchObjectError(req.dn.toString()));
          }

          const user = users[0];
          let mod, authing;

          for (var i = 0; i < req.changes.length; i++) {
            mod = req.changes[i].modification;

            switch (req.changes[i].operation) {
              case 'replace':
                const typeMapping = {
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

                let fieldModified = mod.type;

                if (typeMapping[mod.type]) {
                  fieldModified = typeMapping[mod.type];
                }

                try {
                  authing =
                    authing ||
                    (await new Authing({
                      clientId: req.currentClientId,
                      secret: client.secret,
                    }));

                  if (
                    fieldModified instanceof String ||
                    typeof fieldModified === 'string'
                  ) {
                    let query = {
                      _id: user._id,
                    };
                    const field = fieldModified;
                    query[field] = mod.vals[0];
                    await authing.update(query);
                  } else {
                    let query = {
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
});
//# sourceMappingURL=ldap-idp.umd.development.js.map
