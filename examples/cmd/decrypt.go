package cmd

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

var decryptAlg string

func init() {
	decryptCmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt TDF file",
		RunE:  decrypt,
		Args:  cobra.MinimumNArgs(1),
	}
	decryptCmd.Flags().StringVarP(&decryptAlg, "rewrap-encapsulation-algorithm", "A", "rsa:2048", "Key wrap response algorithm algorithm:parameters")
	decryptCmd.Flags().StringVar(&magicWord, "magic-word", "", "Use a 'magic word' as a shared secret.")
	decryptCmd.Flags().StringVar(&privateKeyPath, "private-key-path", "", "Private key for signing assertions")
	ExamplesCmd.AddCommand(decryptCmd)
}

func decrypt(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return cmd.Usage()
	}

	tdfFile := args[0]

	// Create new client
	client, err := newSDK()
	if err != nil {
		return err
	}
	// Collection
	if stat, err := os.Stat(tdfFile); err == nil && stat.IsDir() {
		entries, err := os.ReadDir(tdfFile)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				f, err := os.Open(filepath.Join(tdfFile, entry.Name()))
				if err != nil {
					return err
				}
				_, err = client.ReadNanoTDF(os.Stdout, f)
				fmt.Println()
				if err != nil {
					return err
				}
			}
		}
		client.Close()
		return nil
	}

	file, err := os.Open(tdfFile)
	if err != nil {
		return err
	}
	defer file.Close()

	var magic [3]byte
	var isNano bool
	n, err := io.ReadFull(file, magic[:])
	switch {
	case err != nil:
		return err
	case n < 3: //nolint: mnd // All TDFs are more than 2 bytes
		return errors.New("file too small; no magic number found")
	case bytes.HasPrefix(magic[:], []byte("L1L")):
		isNano = true
	default:
		isNano = false
	}
	_, err = file.Seek(0, 0)
	if err != nil {
		return err
	}

	if !isNano {
		opts := []sdk.TDFReaderOption{}
		if decryptAlg != "" {
			kt, err := keyTypeForKeyType(decryptAlg)
			if err != nil {
				return err
			}
			opts = append(opts, sdk.WithSessionKeyType(kt))
		}

		// Magic word validator
		if magicWord != "" {
			// Magic word provider with state, this works in a simple CLI
			magicWordProvider := NewMagicWordAssertionProvider(magicWord)
			magicWordPattern := regexp.MustCompile("^" + MagicWordAssertionID + "$")
			opts = append(opts, sdk.WithAssertionValidator(magicWordPattern, magicWordProvider))
		}
		// Public key validator
		if privateKeyPath != "" {
			key := getAssertionKeyPublic(privateKeyPath)
			keys := sdk.AssertionVerificationKeys{
				Keys: map[string]sdk.AssertionKey{
					sdk.KeyAssertionID: key,
				},
			}
			keyValidator := sdk.NewKeyAssertionValidator(keys)
			keyPattern := regexp.MustCompile("^" + sdk.KeyAssertionID)
			opts = append(opts, sdk.WithAssertionValidator(keyPattern, keyValidator))
		}
		// Enable assertion verification
		opts = append(opts, sdk.WithDisableAssertionVerification(false))
		tdfreader, err := client.LoadTDF(file, opts...)
		if err != nil {
			return err
		}

		// Print decrypted string
		_, err = io.Copy(os.Stdout, tdfreader)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
	} else {
		_, err = client.ReadNanoTDF(os.Stdout, file)
		if err != nil {
			return err
		}
	}
	return nil
}

func getAssertionKeyPublic(path string) sdk.AssertionKey {
	privPEM, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(privPEM)
	if block == nil {
		panic("no PEM block found")
	}

	// If the private key is encrypted, you'll need the passphrase and to decrypt first.
	// This snippet expects an unencrypted PKCS#1 or PKCS#8 key.
	var rsaPriv *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsaPriv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			panic(err)
		}
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			panic(err)
		}
		var ok bool
		rsaPriv, ok = key.(*rsa.PrivateKey)
		if !ok {
			panic(errors.New("not an RSA private key"))
		}
	default:
		panic(fmt.Errorf("unsupported key type: %s", block.Type))
	}

	// Extract RSA public key
	rsaPub := &rsaPriv.PublicKey
	return sdk.AssertionKey{
		Alg: sdk.AssertionKeyAlgRS256,
		Key: rsaPub,
	}
}
