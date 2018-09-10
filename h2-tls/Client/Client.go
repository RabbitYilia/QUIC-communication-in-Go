package main

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

func main() {
	versions := protocol.SupportedVersions
	versions = append([]protocol.VersionNumber{protocol.VersionTLS}, versions...)

	roundTripper := &h2quic.RoundTripper{
		QuicConfig:      &quic.Config{Versions: versions},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	defer roundTripper.Close()

	hclient := &http.Client{
		Transport: roundTripper,
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
