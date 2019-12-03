# docker build . -t ldap-idp
# docker run --name ldap-idp -v xxxxx:/app -p 1389:1389 -d ldap-idp
FROM node:9
VOLUME [ "/app" ]
WORKDIR /app/dist
EXPOSE 1389
CMD ["node","index.js"]
