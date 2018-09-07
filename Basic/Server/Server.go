package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"math/big"

	quic "github.com/lucas-clemente/quic-go"
)

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	listener, err := quic.ListenAddr("127.0.0.1:6060", generateTLSConfig(), nil)
	if err != nil {
		log.Fatalln(err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalln(err)
		}
		go Server(conn)
	}
}

// Start a server that echos all data on the first stream opened by the client
func Server(conn quic.Session) {
	stream, err := conn.AcceptStream()
	if err != nil {
		conn.Close()
		log.Println(err)
		return
	}
	for {
		message := make([]byte, 1048576)
		messagelen, err := stream.Read(message)
		if err != nil {
			stream.Close()
			conn.Close()
			log.Println(err)
			return
		}
		if messagelen == 0 {
			continue
		}
		log.Println(string(message[:messagelen]))
		stream.Write([]byte("Get"))
	}
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}
