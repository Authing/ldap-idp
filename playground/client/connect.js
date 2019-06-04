var ldap = require('ldapjs');
var client = ldap.createClient({
  url: 'ldap://0.0.0.0:1389',
});

client.bind(
  'ou=users, o=5c668c712e450b00017af455, dc=authing, dc=cn',
  'adafbe8412cb43293f4f739a5e9ef709',
  function(err, res) {
    console.log(err);
    if (err) {
      console.log(err);
    } else {
      console.log(res);
    }
  }
);
