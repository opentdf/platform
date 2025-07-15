package cmd

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/service/internal/security"
	"github.com/opentdf/platform/service/trust"
	"github.com/spf13/cobra"
)

var (
	verbose bool
	output  string
	inplace bool
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
			if inplace {
				if _, err := exec.LookPath("yq"); err != nil {
					return errors.New("yq not found in PATH, please install it to use the --inplace flag")
				}
			}
			ks, err := keysInit()
			if err != nil {
				cmd.PrintErrf("failed to initialize keys: %v", err)
				return err
			}

			if !inplace {
				if len(ks) > 0 {
					var keyInfos []security.KeyPairInfo
					for _, k := range ks {
						keyInfos = append(keyInfos, security.KeyPairInfo{
							Private:     k.PrivateFile,
							Certificate: k.PublicFile,
							Algorithm:   string(k.Algorithm),
							KID:         string(k.KID),
						})
					}
					b, err := yaml.Marshal(&keyInfos)
					if err != nil {
						cmd.PrintErrf("failed to marshal keys: %v", err)
						return err
					}
					cmd.Print(string(b))
				}
				return nil
			}

			// Inplace update
			for _, k := range ks {
				keyInfo := fmt.Sprintf(`{"private": "%s", "cert": "%s", "kid": "%s", "alg": "%s"}`, k.PrivateFile, k.PublicFile, k.KID, k.Algorithm)
				yqCmd := exec.Command("yq", "-i", fmt.Sprintf(`.server.cryptoProvider.standard.keys += [%s]`, keyInfo), "opentdf.yaml") //nolint:gosec //validated earlier
				if verbose {
					cmd.Println(yqCmd.String())
				}
				if output, err := yqCmd.CombinedOutput(); err != nil {
					return fmt.Errorf("failed to update opentdf.yaml with key info (is yq installed?): %w\n%s", err, output)
				}

				keyringInfo := fmt.Sprintf(`{"kid": "%s", "alg": "%s"}`, k.KID, k.Algorithm)
				yqCmd = exec.Command("yq", "-i", fmt.Sprintf(`.services.kas.keyring += [%s]`, keyringInfo), "opentdf.yaml") //nolint:gosec //validated earlier
				if verbose {
					cmd.Println(yqCmd.String())
				}
				if output, err := yqCmd.CombinedOutput(); err != nil {
					return fmt.Errorf("failed to update opentdf.yaml with keyring info: %w\n%s", err, output)
				}
			}
			cmd.Println("opentdf.yaml updated")

			return nil
		},
	}
	initCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "verbose logging")
	initCmd.Flags().StringVarP(&output, "output", "o", ".", "directory to store new keys to")
	initCmd.Flags().BoolVarP(&inplace, "inplace", "i", false, "update opentdf.yaml in-place using yq")
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

	pubPEM, err := priv.AsymEncryption().PublicKeyInPemFormat()
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

func (ek existingKeys) findNewID() (string, error) {
	for {
		b := make([]byte, idLength)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		id := hex.EncodeToString(b)
		id = id[:idLength]
		if !ek.existingIDs[id] {
			return id, nil
		}
	}
}

type existingKeys struct {
	existingIDs map[string]bool
}

func lookupExistingKeys() (*existingKeys, error) {
	files, err := os.ReadDir(output)
	if err != nil {
		return nil, fmt.Errorf("failed to read output directory [%s]: %w", output, err)
	}

	existingIDs := make(map[string]bool)
	for _, file := range files {
		matches := re.FindStringSubmatch(file.Name())
		if len(matches) > 2 { //nolint:mnd // found a match for the regex
			existingIDs[matches[2]] = true // store the key id
		}
	}

	return &existingKeys{existingIDs: existingIDs}, nil
}

func (ek *existingKeys) getNamesFor(alg string) (string, string, trust.KeyIdentifier, error) {
	id := string(alg[0]) + "1"
	var err error
	if ek.existingIDs[id] {
		// generate a new id
		id, err = ek.findNewID()
		if err != nil {
			return "", "", "", fmt.Errorf("failed to generate new id: %w", err)
		}
	}
	kid, err := trust.NewKeyIdentifier(id)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create key identifier: %w", err)
	}
	kid, err := trust.NewKeyIdentifier(id)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create key identifier: %w", err)
	}

	// return the new file names
	privateFile := fmt.Sprintf("%s/kas-%s-%s-private.pem", output, alg, id)
	publicFile := fmt.Sprintf("%s/kas-%s-%s-public.pem", output, alg, id)
	return privateFile, publicFile, kid, nil
}

type NewKeyInfo struct {
	PrivateFile string
	PublicFile  string
	Algorithm   ocrypto.KeyType
	KID         trust.KeyIdentifier
}

func keysInit() ([]NewKeyInfo, error) {
	var keyPairs []NewKeyInfo
	ek, err := lookupExistingKeys()
	if err != nil {
		return keyPairs, fmt.Errorf("failed to lookup existing keys: %w", err)
	}
	for _, kt := range []ocrypto.KeyType{ocrypto.RSA2048Key, ocrypto.EC256Key, ocrypto.MLKEM768Key} {
		keyRSA, err := ocrypto.Generate(kt)
		if err != nil {
			return keyPairs, fmt.Errorf("unable to generate rsa key [%w]", err)
		}
		fullName := string(kt)
		shortName := strings.Replace(fullName, ":", "-", 1)
		privateFile, publicFile, id, err := ek.getNamesFor(shortName)
		if err != nil {
			return keyPairs, err
		}
		if err := storeKeyPair(keyRSA, privateFile, publicFile); err != nil {
			return keyPairs, err
		}
		keyPairs = append(keyPairs, NewKeyInfo{
			PrivateFile: privateFile,
			PublicFile:  publicFile,
			Algorithm:   kt,
			KID:         id,
		})
	}
	return keyPairs, nil
}
