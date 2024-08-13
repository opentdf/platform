package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
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
		NotAfter:              time.Now().Add(time.Hour * 24 * 30 * 365), //nolint:mnd // a year or so
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
	if err := os.WriteFile(privateFile, keyPEM, 0o600); err != nil {
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

	if err := os.WriteFile(publicFile, pubPEM, 0o600); err != nil {
		return fmt.Errorf("unable to store rsa public key [%w]", err)
	}
	return nil
}

func storeTo(priv, pub jwk.Set, k interface{ Public() crypto.PublicKey }, kid string) error {
	privJWK, err := jwk.FromRaw(k)
	if err != nil {
		return fmt.Errorf("unable to convert private key [%s]: [%w]", kid, err)
	}
	if err := privJWK.Set("kid", kid); err != nil {
		return fmt.Errorf("unable to set kid [%s]: [%w]", kid, err)
	}
	if err := priv.AddKey(privJWK); err != nil {
		return fmt.Errorf("unable to store private key [%s]: [%w]", kid, err)
	}

	pubJWK, err := jwk.FromRaw(k.Public())
	if err != nil {
		return fmt.Errorf("unable to convert public key [%s]: [%w]", kid, err)
	}
	if err := pubJWK.Set("kid", kid); err != nil {
		return fmt.Errorf("unable to set public key kid [%s]: [%w]", kid, err)
	}
	if err := pub.AddKey(pubJWK); err != nil {
		return fmt.Errorf("unable to store public key [%s]: [%w]", kid, err)
	}
	return nil
}

func storeJSON(f string, o any, perm os.FileMode) error {
	s, err := json.Marshal(o)
	if err != nil {
		return fmt.Errorf("unable to marshal key to write to file [%s]: [%w]", f, err)
	}
	if err := os.WriteFile(f, s, perm); err != nil {
		return fmt.Errorf("unable to store key to file [%s]: [%w]", f, err)
	}
	return nil
}

func keysInit() error {
	jwksPriv := jwk.NewSet()
	jwksPub := jwk.NewSet()

	// openssl req -x509 -nodes -newkey RSA:2048
	//  -subj "/CN=kas" -keyout "$opt_output/kas-private.pem" -out "$opt_output/kas-cert.pem" -days 365
	// Generate RSA key.
	keyRSA, err := rsa.GenerateKey(rand.Reader, 2048) //nolint:mnd // 512 byte rsa key
	if err != nil {
		return fmt.Errorf("unable to generate rsa key [%w]", err)
	}
	if err := storeKeyPair(keyRSA, keyRSA.Public(), output+"/kas-private.pem", output+"/kas-cert.pem"); err != nil {
		return err
	}
	if err := storeTo(jwksPriv, jwksPub, keyRSA, "r1"); err != nil {
		return err
	}

	// openssl ecparam -name prime256v1 >ecparams.tmp
	// openssl req -x509 -nodes -newkey ec:ecparams.tmp -subj "/CN=kas" -keyout "$opt_output/kas-ec-private.pem" -out "$opt_output/kas-ec-cert.pem" -days 365
	keyEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate new ECDSA private key: %w", err)
	}
	if err := storeKeyPair(keyEC, keyEC.Public(), output+"/kas-ec-private.pem", output+"/kas-ec-cert.pem"); err != nil {
		return err
	}
	if err := storeTo(jwksPriv, jwksPub, keyEC, "e1"); err != nil {
		return err
	}

	// Store jwk sets kas-public-jwk-set.json and kas-private-jwk-set.json
	if err := storeJSON(output+"/kas-public-jwk-set.json", jwksPub, 0o640); err != nil { //nolint:mnd // u+rw,g+r
		return err
	}
	if err := storeJSON(output+"/kas-private-jwk-set.json", jwksPriv, 0o600); err != nil { //nolint:mnd // u+rw
		return err
	}

	return nil
}
