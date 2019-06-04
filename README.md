# LDAP IdP

An LDAP IdP compatible with [Authing](https://authing.cn).

## 使用方法

| Hostname                | ldap.authing.cn                                                      |
| ----------------------- | -------------------------------------------------------------------- |
| URI/Port                | ldap://ldap.authing.cn:1389                                          |
| LDAP Distinguished Name | cn=AUTHING_USERNAME, ou=users,o=AUTHING_CLINET_ID, dc=authing, dc=cn |
| BaseDN                  | ou=users, o=AUTHING_CLINET_ID, dc=authing, dc=cn                     |

### 认证方式

访问 LDAP 服务器需要使用 Authing 的应用 Secret，如下所示：

```shell
$ ldapsearch -H ldap://ldap.authing.cn:1389 -x -D "ou=users,o=AUTHING_CLIENT_ID,dc=authing,dc=cn" -w "AUTHING_CLIEENT_SECRET"  -LLL -b "ou=users,o=AUTHING_CLIENT_ID,dc=authing,dc=cn"
```

若 Secret 不正确会返回如下信息：

```shell
ldap_bind: Invalid credentials (49)
	matched DN: ou=users, o=AUTHING_CLIENT_ID, dc=authing, dc=cn
	additional info: InvalidCredentialsError
```

### Search

```shell
$ ldapsearch -H ldap://ldap.authing.cn:1389 -x -D "ou=users,o=AUTHING_CLIENT_ID,dc=authing,dc=cn" -w "AUTHING_CLIEENT_SECRET"  -LLL -b "ou=users,o=AUTHING_CLIENT_ID,dc=authing,dc=cn"
```

### Add

创建一个名为 `user.ldif` 的文件然后复制以下内容进去：

```
dn: cn=authingUserName, ou=users, o=AUTHING_CLIENT_ID, dc=authing, dc=cn
objectClass: users
cn: authingUserName
```

然后执行以下命令：

```shell
$ ldapadd -H ldap://ldap.authing.cn:1389 -x -D "ou=users,o=AUTHING_CLIENT_ID,dc=authing,dc=cn" -w "AUTHING_CLIEENT_SECRET" -f ./user.ldif
```

### Modify

创建一个名为 `modify.ldif` 的文件然后复制以下内容进去：

```
dn: cn=secret, ou=users, o=AUTHING_CLIENT_ID, dc=authing, dc=cn
changetype: replace
replace: userPassword
userPassword: 18000179178
```

然后执行以下命令：

```shell
$ ldapmodify -H ldap://ldap.authing.cn:1389 -x -D "ou=users,o=AUTHING_CLIENT_ID,dc=authing,dc=cn" -w "AUTHING_CLIEENT_SECRET" -f ./modify.ldif
```

### Delete

```shell
$ ldapdelete -H ldap://ldap.authing.cn:1389 -x -D "ou=users,o=AUTHING_CLIENT_ID,dc=authing,dc=cn" -w "AUTHING_CLIEENT_SECRET" "cn=authingUserName, ou=users, o=AUTHING_CLIENT_ID,dc=authing,dc=cn"
```

## Local Development

Below is a list of commands you will probably find useful.

### `npm start` or `yarn start`

Runs the project in development/watch mode. Your project will be rebuilt upon changes. TSDX has a special logger for you convenience. Error messages are pretty printed and formatted for compatibility VS Code's Problems tab.

<img src="https://user-images.githubusercontent.com/4060187/52168303-574d3a00-26f6-11e9-9f3b-71dbec9ebfcb.gif" width="600" />

Your library will be rebuilt if you make edits.

### `npm run build` or `yarn build`

Bundles the package to the `dist` folder.
The package is optimized and bundled with Rollup into multiple formats (CommonJS, UMD, and ES Module).

<img src="https://user-images.githubusercontent.com/4060187/52168322-a98e5b00-26f6-11e9-8cf6-222d716b75ef.gif" width="600" />

### `npm test` or `yarn test`

Runs the test watcher (Jest) in an interactive mode.
By default, runs tests related to files changed since the last commit.
