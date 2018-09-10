package main

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/lucas-clemente/quic-go/h2quic"
)

func main() {
	hclient := &http.Client{
		Transport: &h2quic.RoundTripper{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	resp, err := hclient.Get("https://127.0.0.1:6161/")
	if err != nil {
		log.Println(err)
		return
	}
	bytebody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()
	content := string(bytebody)
	log.Println(content)
}
