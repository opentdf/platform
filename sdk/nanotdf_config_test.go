package sdk

import (
	"github.com/opentdf/platform/lib/ocrypto"
	"testing"
)

// TestNanoTDFConfig1 - Create a new config, verify that the config contains valid PEMs for the key pair
func TestNanoTDFConfig1(t *testing.T) {

	var s SDK
	conf, err := s.NewNanoTDFConfig()
	if err != nil {
		t.Fatal(err)
	}
	pemPubKey, err := ocrypto.ECPrivateKeyInPemFormat(*conf.keyPair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(pemPubKey) == 0 {
		t.Fatal("no public key")
	}

	privateKey, err := ocrypto.ECPublicKeyInPemFormat(conf.keyPair.PrivateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(privateKey) == 0 {
		t.Fatal("no private key")
	}
}

// TestNanoTDFConfig2 - set kas url, retrieve kas url, verify value is correct
func TestNanoTDFConfig2(t *testing.T) {
	const (
		kasUrl = "https://test.virtru.com"
	)

	var s SDK
	conf, err := s.NewNanoTDFConfig()
	if err != nil {
		t.Fatal(err)
	}
	err = conf.SetKasUrl(kasUrl)
	if err != nil {
		t.Fatal(err)
	}

	readKasUrl, err := conf.kasURL.getUrl()
	if err != nil {
		t.Fatal(err)
	}
	if readKasUrl != kasUrl {
		t.Fatalf("expect %s, got %s", kasUrl, readKasUrl)
	}
}
