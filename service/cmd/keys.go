package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var (
	verbose bool
	output  string
)

func init() {
	keysCmd := cobra.Command{
		Use:   "keys",
		Short: "Initialize and manage KAS public keys",
	}

	initCmd := &cobra.Command{
		Use:  "init",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return keysInit()
		},
	}
	initCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "verbose logging")
	initCmd.Flags().StringVarP(&output, "output", "o", ".", "directory to store new keys to")
	keysCmd.AddCommand(initCmd)

	rootCmd.AddCommand(&keysCmd)
}

func CertTemplate() (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128) //nolint:mnd // 128 bit uid is sufficiently unique
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number [%w]", err)
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "kas"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 30 * 365), //nolint:mnd // About a year to expire
		BasicConstraintsValid: true,
	}
	return &tmpl, nil
}

func storeKeyPair(priv, pub any, privateFile, publicFile string) error {
	privateBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("unable to marshal private key [%w]", err)
	}
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateBytes,
		},
	)
	if err := os.WriteFile(privateFile, keyPEM, 0o400); err != nil {
		return fmt.Errorf("unable to store key [%w]", err)
	}

	certTemplate, err := CertTemplate()
	if err != nil {
		return fmt.Errorf("unable to create cert template [%w]", err)
	}

	pubBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, pub, priv)
	if err != nil {
		return fmt.Errorf("unable to create cert [%w]", err)
	}
	_, err = x509.ParseCertificate(pubBytes)
	if err != nil {
		return fmt.Errorf("unable to parse cert [%w]", err)
	}
	// Encode public key to PKCS#1 ASN.1 PEM.
	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: pubBytes,
		},
	)

	if err := os.WriteFile(publicFile, pubPEM, 0o400); err != nil {
		return fmt.Errorf("unable to store rsa public key [%w]", err)
	}
	return nil
}

func keysInit() error {
	// openssl req -x509 -nodes -newkey RSA:2048
	//  -subj "/CN=kas" -keyout "$opt_output/kas-private.pem" -out "$opt_output/kas-cert.pem" -days 365
	// Generate RSA key.
	keyRSA, err := rsa.GenerateKey(rand.Reader, 2048) //nolint:mnd // 256 byte key
	if err != nil {
		return fmt.Errorf("unable to generate rsa key [%w]", err)
	}
	if err := storeKeyPair(keyRSA, keyRSA.Public(), output+"/kas-private.pem", output+"/kas-cert.pem"); err != nil {
		return err
	}

	// openssl ecparam -name prime256v1 >ecparams.tmp
	// openssl req -x509 -nodes -newkey ec:ecparams.tmp -subj "/CN=kas" -keyout "$opt_output/kas-ec-private.pem" -out "$opt_output/kas-ec-cert.pem" -days 365
	keyEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ECDSA private key [%w]", err)
	}
	if err := storeKeyPair(keyEC, keyEC.Public(), output+"/kas-ec-private.pem", output+"/kas-ec-cert.pem"); err != nil {
		return err
	}

	return nil
}
