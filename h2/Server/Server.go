package main

import (
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/lucas-clemente/quic-go/h2quic"
	aead "golang.org/x/crypto/chacha20poly1305"
)

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	router := httprouter.New()
	router.GET("/", index)
	h2quic.ListenAndServeQUIC("localhost:6161", "./server.crt", "./server.key", router)

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
