package sdk

import (
	"testing"

	"github.com/stretchr/testify/require"
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

func TestNewNanoTDFConfigWithMultipleOptions(t *testing.T) {
	s := SDK{}
	optionOne := func(c *NanoTDFConfig) error {
		c.cipher = cipherModeAes256gcm96Bit
		return nil
	}
	optionTwo := func(c *NanoTDFConfig) error {
		c.bindCfg.useEcdsaBinding = true
		return nil
	}
	config, err := s.newNanoTDFConfig(optionOne, optionTwo)
	require.NoError(t, err)
	require.NotNil(t, config)
	require.Equal(t, cipherModeAes256gcm96Bit, config.cipher)
	require.True(t, config.bindCfg.useEcdsaBinding)
}
