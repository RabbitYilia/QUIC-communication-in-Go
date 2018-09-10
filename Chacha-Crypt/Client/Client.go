package main

import (
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
	h := sha256.New()
	h.Write([]byte(key))
	ciper, err := aead.New(h.Sum(nil))
	recvbuffer := make([]byte, 1048576)
	message := "foobar"
	fmt.Printf("Client: Sending '%s'\n", message)
	nonceint := int(time.Now().Unix()/300) * 300
	noncestr := strconv.Itoa(nonceint)
	h.Reset()
	h.Write([]byte(noncestr))
	nonce := h.Sum(nil)[:12]
	ciphertext := ciper.Seal(nil, nonce, []byte(message), nil)
	_, err = stream.Write(ciphertext)
	if err != nil {
		log.Panicln(err)
		return
	}
	recvmsglen, err := stream.Read(recvbuffer)
	nonceint = int(time.Now().Unix()/300) * 300
	noncestr = strconv.Itoa(nonceint)
	h.Reset()
	h.Write([]byte(noncestr))
	nonce = h.Sum(nil)[:12]
	plaintext, err := ciper.Open(nil, nonce, recvbuffer[:recvmsglen], nil)
	log.Println(string(plaintext))
}
