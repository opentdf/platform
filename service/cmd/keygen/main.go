// Package main generates hybrid post-quantum KAS key pairs (X-Wing, P256+ML-KEM-768, P384+ML-KEM-1024)
// as PEM files for use with the OpenTDF platform.
package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/opentdf/platform/lib/ocrypto"
)

type keySpec struct {
	name       string
	newKeyPair func() (privatePEM, publicPEM string, err error)
	privateOut string
	publicOut  string
}

func main() {
	outputDir := flag.String("output", ".", "directory to write PEM files")
	flag.Parse()

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		log.Fatalf("failed to create output directory: %v", err)
	}

	specs := []keySpec{
		{
			name:       "X-Wing",
			newKeyPair: generateXWing,
			privateOut: "kas-xwing-private.pem",
			publicOut:  "kas-xwing-public.pem",
		},
		{
			name:       "P256+ML-KEM-768",
			newKeyPair: generateP256MLKEM768,
			privateOut: "kas-p256mlkem768-private.pem",
			publicOut:  "kas-p256mlkem768-public.pem",
		},
		{
			name:       "P384+ML-KEM-1024",
			newKeyPair: generateP384MLKEM1024,
			privateOut: "kas-p384mlkem1024-private.pem",
			publicOut:  "kas-p384mlkem1024-public.pem",
		},
	}

	for _, s := range specs {
		privatePEM, publicPEM, err := s.newKeyPair()
		if err != nil {
			log.Fatalf("failed to generate %s key pair: %v", s.name, err)
		}

		privPath := filepath.Join(*outputDir, s.privateOut)
		pubPath := filepath.Join(*outputDir, s.publicOut)

		if err := os.WriteFile(privPath, []byte(privatePEM), 0o600); err != nil {
			log.Fatalf("failed to write %s: %v", privPath, err)
		}
		if err := os.WriteFile(pubPath, []byte(publicPEM), 0o600); err != nil {
			log.Fatalf("failed to write %s: %v", pubPath, err)
		}

		log.Printf("Generated %s key pair:\n  - Private: %s\n  - Public:  %s", s.name, privPath, pubPath)
	}
}

func generateXWing() (string, string, error) {
	kp, err := ocrypto.NewXWingKeyPair()
	if err != nil {
		return "", "", err
	}
	priv, err := kp.PrivateKeyInPemFormat()
	if err != nil {
		return "", "", err
	}
	pub, err := kp.PublicKeyInPemFormat()
	if err != nil {
		return "", "", err
	}
	return priv, pub, nil
}

func generateP256MLKEM768() (string, string, error) {
	kp, err := ocrypto.NewP256MLKEM768KeyPair()
	if err != nil {
		return "", "", err
	}
	priv, err := kp.PrivateKeyInPemFormat()
	if err != nil {
		return "", "", err
	}
	pub, err := kp.PublicKeyInPemFormat()
	if err != nil {
		return "", "", err
	}
	return priv, pub, nil
}

func generateP384MLKEM1024() (string, string, error) {
	kp, err := ocrypto.NewP384MLKEM1024KeyPair()
	if err != nil {
		return "", "", err
	}
	priv, err := kp.PrivateKeyInPemFormat()
	if err != nil {
		return "", "", err
	}
	pub, err := kp.PublicKeyInPemFormat()
	if err != nil {
		return "", "", err
	}
	return priv, pub, nil
}
