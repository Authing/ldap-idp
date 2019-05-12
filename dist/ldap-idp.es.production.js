const e=require("ldapjs");function r(r,t,n){var o=r instanceof e.SearchRequest;return r.connection.ldap.bindDN.equals("cn=root")||o?n():n(new e.InsufficientAccessRightsError)}var t="o=joyent",n={},o=e.createServer();o.bind("cn=root",function(r,t,n){return"cn=root"!==r.dn.toString()||"secret"!==r.credentials?n(new e.InvalidCredentialsError):(t.end(),n())}),o.add(t,r,function(r,t,o){var a=r.dn.toString();return n[a]?o(new e.EntryAlreadyExistsError(a)):(n[a]=r.toObject().attributes,t.end(),o())}),o.bind(t,function(r,t,o){var a=r.dn.toString();return n[a]?n[a].userpassword?-1===n[a].userpassword.indexOf(r.credentials)?o(new e.InvalidCredentialsError):(t.end(),o()):o(new e.NoSuchAttributeError("userPassword")):o(new e.NoSuchObjectError(a))}),o.compare(t,r,function(r,t,o){var a=r.dn.toString();if(!n[a])return o(new e.NoSuchObjectError(a));if(!n[a][r.attribute])return o(new e.NoSuchAttributeError(r.attribute));for(var c=!1,i=n[a][r.attribute],u=0;u<i.length;u++)if(i[u]===r.value){c=!0;break}return t.end(c),o()}),o.del(t,r,function(r,t,o){var a=r.dn.toString();return n[a]?(delete n[a],t.end(),o()):o(new e.NoSuchObjectError(a))}),o.modify(t,r,function(r,t,o){const a=r.dn.toString();let c=null;if(!r.changes.length)return o(new e.ProtocolError("changes required"));if(!n[a])return o(new e.NoSuchObjectError(a));for(var i=n[a],u=0;u<r.changes.length;u++)switch(c=r.changes[u].modification,r.changes[u].operation){case"replace":if(!i[c.type])return o(new e.NoSuchAttributeError(c.type));c.vals&&c.vals.length?i[c.type]=c.vals:delete i[c.type];break;case"add":i[c.type]?c.vals.forEach(function(e){-1===i[c.type].indexOf(e)&&i[c.type].push(e)}):i[c.type]=c.vals;break;case"delete":if(!i[c.type])return o(new e.NoSuchAttributeError(c.type));delete i[c.type]}return t.end(),o()}),o.search(t,r,function(r,t,o){var a,c=r.dn.toString();if(!n[c])return o(new e.NoSuchObjectError(c));switch(r.scope){case"base":return r.filter.matches(n[c])&&t.send({dn:c,attributes:n[c]}),t.end(),o();case"one":a=function(t){if(r.dn.equals(t))return!0;var n=e.parseDN(t).parent();return!!n&&n.equals(r.dn)};break;case"sub":a=function(e){return r.dn.equals(e)||r.dn.parentOf(e)}}return Object.keys(n).forEach(function(e){a(e)&&r.filter.matches(n[e])&&t.send({dn:e,attributes:n[e]})}),t.end(),o()}),o.listen(1389,function(){console.log("LDAP server up at: %s",o.url)});
//# sourceMappingURL=ldap-idp.es.production.js.map
