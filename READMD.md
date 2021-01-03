# Setup

Enter no data during the certification creation process, just press ENTER.

```
cd script 

./dumper.sh (as root)
run ./server.sh in a different shell
run ./client.sh in a different shell
```
Then send in the client shell for example:
SECRET DATA SHARED

Then stop all software:
```
kill client with CTRL+C
kill server with CTRL+C
stop listening and CTRL+C dumper
```
you should have now everything you need to decrypt traffic:
for example:
```
go run main.go -r script/com.pcap -decrypt 2020 -sslkeylog script/premaster.txt 
12:16AM INF packet/packet.go:90 > Starting to read packets
127.0.0.1->127.0.0.1 40862->2020 hello,world

127.0.0.1->127.0.0.1 40862->2020 你好,世界
 
127.0.0.1->127.0.0.1 40862->2020 こんにちは、世界
 
127.0.0.1->127.0.0.1 40862->2020 Здравствуй мир

```

END

# Notes

You can try to use chromium with 'chromium ssl-key-log-file="premaster.txt"', but you will have to need all ciphers.
I recommend for testing cipher stuff a custom openssl build, containing all you need.

pcap with the connection
master client keys in premaster.txt 
Key_Log_Format see https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format

The openssl version is (OpenSSL 1.1.1f  31 Mar 2020), it contains all ciphers (especially the weak ones) and is useful for testing.


# Dependencies

* gopacket and TLS/SSL Extension
* Go 1.14 or higher, but Go 1.14 branch for mine !
* openssl (you can also use the delivered binary (default))
* go crypto/tls, hmac, hashlib, binascii should be in standard golang installation
* tcpdump -> run dumper.sh as root!
* bash shell is called in some scripts. This can be changed easily if you don't have bash


# Other

Thank you for https://github.com/fxb-cocacoding/ssl_decrypt