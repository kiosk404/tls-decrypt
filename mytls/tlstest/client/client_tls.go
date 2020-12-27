package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	tls "netAnalyzer/example/mytls"
	"os"
)

func main() {
	cert, err := tls.LoadX509KeyPair("../certs/client.pem", "../certs/client.key")
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}

	f, err := os.OpenFile("sslkey.log",os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Println(err)
		return
	}
	//defer f.Close()
	w := bufio.NewWriter(f)

	config := tls.Config{
		Certificates: []tls.Certificate{cert},
		InsecureSkipVerify: true,
		KeyLogWriter:w,
	}
	conn, err := tls.Dial("tcp", "127.0.0.1:4443", &config)
	if err != nil {
		log.Fatalf("client: dial: %s", err)
	}
	defer conn.Close()
	log.Println("client: connected to: ", conn.RemoteAddr())

	state := conn.ConnectionState()
	//for _, v := range state.PeerCertificates {
	//	fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
	//	fmt.Println(v.Subject)
	//}
	log.Println("client: handshake: ", state.HandshakeComplete)
	log.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)

	message := "Hello Server !!\n"
	n, err := io.WriteString(conn, message)
	if err != nil {
		log.Fatalf("client: write: %s", err)
	}
	log.Printf("client: wrote %q (%d bytes)", message, n)

	reply := make([]byte, 256)
	n, err = conn.Read(reply)
	log.Printf("client: read %q (%d bytes)", string(reply[:n]), n)
	log.Print("client: exiting")
}