#!/bin/bash

openssl genrsa -out MyRootCA.key 2048
openssl req -x509 -new -nodes -key MyRootCA.key -sha256 -days 1024 -out MyRootCA.pem
openssl genrsa -out MyServer.key 2048
openssl req -new -key MyServer.key -out MyServer.csr
openssl x509 -req -in MyServer.csr -CA MyRootCA.pem -CAkey MyRootCA.key -CAcreateserial -out MyServer.pem -days 1024 -sha256
