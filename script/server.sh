#!/bin/bash

openssl s_server -tls1_2 -accept 2020 -cert MyServer.pem -key MyServer.key -debug
