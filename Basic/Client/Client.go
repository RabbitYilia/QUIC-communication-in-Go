package main

import (
	"crypto/tls"
	"fmt"
	"log"

	quic "github.com/lucas-clemente/quic-go"
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
	recvbuffer := make([]byte, 1048576)
	message := "foobar"
	fmt.Printf("Client: Sending '%s'\n", message)
	_, err := stream.Write([]byte(message))
	if err != nil {
		log.Panicln(err)
		return
	}
	recvmsglen, err := stream.Read(recvbuffer)
	log.Println(string(recvbuffer[:recvmsglen]))
}
