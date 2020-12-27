#!/bin/bash

openssl s_client -connect 127.0.0.1:2020 -servername kiosk007.top -debug -CAfile MyRootCA.pem -keylogfile premaster.txt
