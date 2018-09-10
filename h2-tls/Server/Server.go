package main

import (
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	quic "QUIC-communication-in-Go/h2-tls/quic-go"
	"QUIC-communication-in-Go/h2-tls/quic-go/ex/protocol"
	"QUIC-communication-in-Go/h2-tls/quic-go/h2quic"

	"github.com/julienschmidt/httprouter"
	aead "golang.org/x/crypto/chacha20poly1305"
)

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	router := httprouter.New()
	router.GET("/", index)

	versions := protocol.SupportedVersions
	versions = append([]protocol.VersionNumber{protocol.VersionTLS}, versions...)

	certFile := "./server.crt"
	keyFile := "./server.key"

	server := h2quic.Server{
		Server:     &http.Server{Addr: "127.0.0.1:6161"},
		QuicConfig: &quic.Config{Versions: versions},
	}
	err := server.ListenAndServeTLS(certFile, keyFile)
	if err != nil {
		log.Println(err)
		return
	}
}

func index(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	fmt.Fprint(w, "Welcome!\n")
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
