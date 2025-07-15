package cmd

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/service/internal/security"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

var (
	verbose bool
	output  string
)

func init() {
	keysCmd := cobra.Command{
		Use:   "keys",
		Short: "Initialize and manage KAS public keys, outputting them to the `-o` directory, and printing out yaml to add to server.cryptoProvider.standard.keys to load them",
	}

	initCmd := &cobra.Command{
		Use:  "init",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ks, err := keysInit()
			if len(ks) > 0 {
				b, err := yaml.Marshal(&ks)
				if err != nil {
					cmd.PrintErrf("failed to marshal keys: %v", err)
					return err
				}
				cmd.Print(string(b))
			}
			if err != nil {
				cmd.PrintErrf("failed to initialize keys: %v", err)
				return err
			}
			return nil
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

func storeKeyPair(priv ocrypto.PrivateKeyDecryptor, privateFile, publicFile string) error {
	keyPEM, err := priv.Export()
	if err != nil {
		return fmt.Errorf("unable to marshal private key [%w]", err)
	}
	if err := os.WriteFile(privateFile, keyPEM, 0o400); err != nil {
		return fmt.Errorf("unable to store key [%w]", err)
	}

	pub, err := priv.AsymEncryption()
	if err != nil {
		return fmt.Errorf("unable to get public key [%w]", err)
	}
	pubPEM, err := pub.PublicKeyInPemFormat()
	if err != nil {
		return fmt.Errorf("unable to marshal public key [%w]", err)
	}
	if err := os.WriteFile(publicFile, []byte(pubPEM), 0o600); err != nil {
		return fmt.Errorf("unable to store rsa public key [%w]", err)
	}
	return nil
}

const (
	idLength = 7
	// KasIDRegexp is a regular expression for parsing KAS key file names.
	KasIDRegexp = `kas-([a-zA-Z0-9]+)-([a-zA-Z0-9]+)-(public|private)\.pem`
)

var re = regexp.MustCompile(KasIDRegexp)

func findNewID(existing map[string]bool) (string, error) {
	for {
		b := make([]byte, idLength)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		id := fmt.Sprintf("%x", b)
		id = id[:idLength]
		if !existing[id] {
			return id, nil
		}
	}
}

func getNamesFor(alg string) (string, string, string, error) {
	// find all existing key ids
	files, err := os.ReadDir(output)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to read output directory [%s]: %w", output, err)
	}

	existingIDs := make(map[string]bool)
	for _, file := range files {
		matches := re.FindStringSubmatch(file.Name())
		if len(matches) > 2 {
			existingIDs[matches[2]] = true
		}
	}

	// generate a new id
	id, err := findNewID(existingIDs)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate new id: %w", err)
	}

	// return the new file names
	privateFile := fmt.Sprintf("%s/kas-%s-%s-private.pem", output, alg, id)
	publicFile := fmt.Sprintf("%s/kas-%s-%s-public.pem", output, alg, id)
	return privateFile, publicFile, id, nil
}

func keysInit() ([]security.KeyPairInfo, error) {
	var keyPairs []security.KeyPairInfo
	for _, kt := range []ocrypto.KeyType{ocrypto.RSA2048Key, ocrypto.EC256Key, ocrypto.MLKEM768Key} {
		keyRSA, err := ocrypto.Generate(kt)
		if err != nil {
			return keyPairs, fmt.Errorf("unable to generate rsa key [%w]", err)
		}
		fullName := string(kt)
		shortName := strings.Replace(fullName, ":", "-", 1)
		privateFile, publicFile, id, err := getNamesFor(shortName)
		if err != nil {
			return keyPairs, err
		}
		if err := storeKeyPair(keyRSA, privateFile, publicFile); err != nil {
			return keyPairs, err
		}
		keyPairs = append(keyPairs, security.KeyPairInfo{
			Private:   privateFile,
			Algorithm: string(kt),
			KID:       id,
		})
	}
	return keyPairs, nil
}
