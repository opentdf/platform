package sdk

import (
	"testing"
)

func TestNanoTDFConfig1(t *testing.T) {

	conf, err := NewNanoTDFConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.publicKey) == 0 {
		t.Fatal("no public key")
	}
	if len(conf.privateKey) == 0 {
		t.Fatal("no private key")
	}

}
