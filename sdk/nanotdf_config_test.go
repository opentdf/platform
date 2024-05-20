package sdk

import (
	"github.com/opentdf/platform/lib/ocrypto"
	"testing"
)

func TestNanoTDFConfig1(t *testing.T) {

	conf, err := NewNanoTDFConfig()
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
