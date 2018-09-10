package main

import (
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"log"
	"strconv"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	aead "golang.org/x/crypto/chacha20poly1305"
)

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	session, err := quic.DialAddr("localhost:6060", &tls.Config{InsecureSkipVerify: true}, nil)
	if err != nil {
		panic(err)
	}
	stream, err := session.OpenStreamSync()
	if err != nil {
		panic(err)
	}
	clientMain(stream)
	session.Close()
}

func clientMain(stream quic.Stream) {
	key := "Password"
	ciper, err := gerateAEAD(key)
	recvbuffer := make([]byte, 1048576)
	message := "foobar"
	fmt.Printf("Client: Sending '%s'\n", message)
	ciphertext := ciper.Seal(nil, geratenonce(), []byte(message), nil)
	_, err = stream.Write(ciphertext)
	if err != nil {
		log.Panicln(err)
		return
	}
	recvmsglen, err := stream.Read(recvbuffer)
	plaintext, err := ciper.Open(nil, geratenonce(), recvbuffer[:recvmsglen], nil)
	log.Println(string(plaintext))
}

func geratenonce() []byte {
	hash := sha256.New()
	hash.Write([]byte(strconv.Itoa(int(time.Now().Unix()/300) * 300)))
	return hash.Sum(nil)[:12]
}

func gerateAEAD(password string) (AEAD cipher.AEAD, err error) {
	hash := sha256.New()
	hash.Write([]byte(password))
	return aead.New(hash.Sum(nil))
}
