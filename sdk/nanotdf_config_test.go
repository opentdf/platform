package sdk

import (
	"testing"
)

// TestNanoTDFConfig1 - Create a new config, verify that the config contains valid PEMs for the key pair
func TestNanoTDFConfig1(t *testing.T) {
	var s SDK
	conf, err := s.NewNanoTDFConfig()
	if err != nil {
		t.Fatal(err)
	}
	pemPrvKey, err := conf.keyPair.PrivateKeyInPemFormat()
	if err != nil {
		t.Fatal(err)
	}

	if len(pemPrvKey) == 0 {
		t.Fatal("no private key")
	}

	pemPubKey, err := conf.keyPair.PublicKeyInPemFormat()
	if err != nil {
		t.Fatal(err)
	}
	if len(pemPubKey) == 0 {
		t.Fatal("no public key")
	}
}

// TestNanoTDFConfig2 - set kas url, retrieve kas url, verify value is correct
func TestNanoTDFConfig2(t *testing.T) {
	const (
		kasURL = "https://test.virtru.com"
	)

	var s SDK
	conf, err := s.NewNanoTDFConfig()
	if err != nil {
		t.Fatal(err)
	}
	err = conf.SetKasURL(kasURL)
	if err != nil {
		t.Fatal(err)
	}

	readKasURL, err := conf.kasURL.getURL()
	if err != nil {
		t.Fatal(err)
	}
	if readKasURL != kasURL {
		t.Fatalf("expect %s, got %s", kasURL, readKasURL)
	}
}
