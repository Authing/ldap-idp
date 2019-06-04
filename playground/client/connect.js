const ldap = require('ldapjs');
const util = require('util');

const client = ldap.createClient({
  url: 'ldap://0.0.0.0:1389',
});

const LDAPUserTest = options => {
  const { username, password, ldapLogin } = options;

  return new Promise((resolve, reject) => {
    client.once('error', err => {
      if (err) {
        let msg = {
          type: false,
          message: `once: ${err}`,
        };
        reject(msg);
      }
    });
    // 注册事件处理函数
    const ldapSearch = (err, search) => {
      const users = [];
      if (err) {
        let msg = {
          type: false,
          message: `ldapSearch: ${err}`,
        };
        reject(msg);
      }
      // 查询结果事件响应
      search.on('searchEntry', entry => {
        if (entry) {
          // 获取查询对象
          users.push(entry.object);
        }
      });
      // 查询错误事件
      search.on('error', e => {
        if (e) {
          let msg = {
            type: false,
            message: `searchErr: ${e}`,
          };
          reject(msg);
        }
      });

      search.on('searchReference', referral => {
        // if (referral) {
        //   let msg = {
        //     type: false,
        //     message: `searchReference: ${referral}`
        //   };
        //   reject(msg);
        // }
        console.log('referral: ' + referral.uris.join());
      });
      // 查询结束
      search.on('end', () => {
        if (users.length > 0) {
          client.bind(users[0].dn, password, e => {
            if (e) {
              let msg = {
                type: false,
                message: `用户名或密码不正确: ${e}`,
              };
              reject(msg);
            } else {
              let msg = {
                type: true,
                message: `验证成功`,
                info: users[0],
              };
              resolve(msg);
            }
            client.unbind();
          });
        } else {
          let msg = {
            type: false,
            message: `用户名不存在`,
          };
          reject(msg);
          client.unbind();
        }
      });
    };
    // 将 client 绑定 LDAP Server
    // 第一个参数： 是用户，必须是从根结点到用户节点的全路径
    // 第二个参数： 用户密码

    return new Promise((resolve, reject) => {
      if (ldapLogin.password) {
        client.bind(ldapLogin.baseDN, ldapLogin.password, err => {
          if (err) {
            let msg = {
              type: false,
              message: `LDAP server 绑定失败: ${err}`,
            };
            reject(msg);
          }

          resolve();
        });
      } else {
        resolve();
      }
    }).then(() => {
      const searchDN = ldapLogin.username;
      const searchStandard = ldapLogin.searchStandard;
      // 处理可以自定义filter
      let customFilter;
      if (/^&/gi.test(searchStandard)) {
        customFilter = util.format(searchStandard, username);
      } else {
        customFilter = `${searchStandard}=${username}`;
      }
      const opts = {
        filter: `(${customFilter})`,
        scope: 'sub',
      };

      console.log(opts);

      // 开始查询
      // 第一个参数： 查询基础路径，代表在查询用户信息将在这个路径下进行，该路径由根结点开始
      // 第二个参数： 查询选项
      client.search(searchDN, opts, ldapSearch);
    });
  });
};

client.bind(
  'ou=users, o=5c668c712e450b00017af455, dc=authing, dc=cn',
  'adafbe8412cb43293f4f739a5e9ef709',
  async function(err, res) {
    console.log(err);
    if (err) {
      console.log(err);
    } else {
      console.log('连接成功，开始查询...');

      const ldapLogin = {
        name: 'authing',
        ldapLink: 'ldap://0.0.0.0:1389',
        description: '',
        baseDN: 'ou=users, o=5c344f102e450b000170190a, dc=authing, dc=cn',
        username:
          'cn=tester, ou=users,o=5c344f102e450b000170190a, dc=authing, dc=cn',
        password: '03bb8b2fca823137c7dec63fd0029fc2',
        searchStandard: 'cn',
        testUsername: 'tester',
        testPassword: '123456',
        clientId: '5c344f102e450b000170190a',
        userId: '5a597f35085a2000144a10ed',
      };

      try {
        const result = await LDAPUserTest({
          username: ldapLogin.testUsername,
          password: ldapLogin.testPassword,
          ldapLogin: ldapLogin,
        });
        console.log(result);
      } catch (err) {
        console.log(err);
      }
    }
  }
);
