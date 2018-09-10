package main

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"

	quic "QUIC-communication-in-Go/h2-tls/quic-go"
	"QUIC-communication-in-Go/h2-tls/quic-go/ex/protocol"
	"QUIC-communication-in-Go/h2-tls/quic-go/h2quic"
)

func main() {
	versions := protocol.SupportedVersions
	versions = append([]protocol.VersionNumber{protocol.VersionTLS}, versions...)

	hclient := &http.Client{
		Transport: &h2quic.RoundTripper{
			QuicConfig: &quic.Config{Versions: versions},
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
