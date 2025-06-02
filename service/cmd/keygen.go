package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/spf13/cobra"
)

var keygenCategories = []string{
	"auth", // Authentication keys
}

var keygenCmd = &cobra.Command{
	Use:   "keygen <" + strings.Join(keygenCategories, "|") + ">",
	Short: "Generate a keypair for a given category (JWK only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		category := args[0]
		outDir, _ := cmd.Flags().GetString("out-dir")
		keyType, _ := cmd.Flags().GetString("type")
		size, _ := cmd.Flags().GetInt("size")
		curve, _ := cmd.Flags().GetString("curve")
		if outDir == "" {
			outDir = "keys"
		}
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return fmt.Errorf("failed to create output dir: %w", err)
		}
		var privKey interface{}
		var keyName string
		var err error
		// Set defaults per category
		switch category {
		case "auth":
			keyName = "client-credentials"
			if keyType == "" {
				keyType = "rsa"
			}
			if size == 0 {
				size = 2048
			}
			if curve == "" {
				curve = "P-256"
			}
		default:
			return fmt.Errorf("unknown category: %s", category)
		}
		switch keyType {
		case "rsa":
			privKey, err = rsa.GenerateKey(rand.Reader, size)
			if err != nil {
				return fmt.Errorf("failed to generate RSA key: %w", err)
			}
		case "ecc", "ec", "ecdsa":
			var ecCurve elliptic.Curve
			switch strings.ToLower(curve) {
			case "p-256", "secp256r1":
				ecCurve = elliptic.P256()
			case "p-384", "secp384r1":
				ecCurve = elliptic.P384()
			case "p-521", "secp521r1":
				ecCurve = elliptic.P521()
			default:
				return fmt.Errorf("unsupported curve: %s", curve)
			}
			privKey, err = ecdsa.GenerateKey(ecCurve, rand.Reader)
			if err != nil {
				return fmt.Errorf("failed to generate EC key: %w", err)
			}
		default:
			return fmt.Errorf("unsupported key type: %s", keyType)
		}
		privJWK, err := jwk.FromRaw(privKey)
		if err != nil {
			return fmt.Errorf("failed to create JWK from private key: %w", err)
		}
		pubKey, err := jwk.PublicKeyOf(privJWK)
		if err != nil {
			return fmt.Errorf("failed to get public JWK: %w", err)
		}
		// Generate kid as base64url(sha256(n)) for RSA, or base64url(sha256(x||y)) for EC
		var kid string
		switch k := pubKey.(type) {
		case jwk.RSAPublicKey:
			nBytes := k.N()
			h := sha256.Sum256(nBytes)
			kid = base64.RawURLEncoding.EncodeToString(h[:])
		case jwk.ECDSAPublicKey:
			xBytes := k.X()
			yBytes := k.Y()
			xy := append(xBytes, yBytes...)
			h := sha256.Sum256(xy)
			kid = base64.RawURLEncoding.EncodeToString(h[:])
		default:
			kid = "custom-key-id"
		}
		_ = privJWK.Set("kid", kid)
		_ = pubKey.Set("kid", kid)
		privJWKJSON, err := json.MarshalIndent(privJWK, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal private JWK: %w", err)
		}
		pubJWKJSON, err := json.MarshalIndent(pubKey, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal public JWK: %w", err)
		}
		privPath := filepath.Join(outDir, keyName+"-private.jwk")
		pubPath := filepath.Join(outDir, keyName+"-public.jwk")
		if err := os.WriteFile(privPath, privJWKJSON, 0o600); err != nil {
			return fmt.Errorf("failed to write private JWK: %w", err)
		}
		if err := os.WriteFile(pubPath, pubJWKJSON, 0o644); err != nil {
			return fmt.Errorf("failed to write public JWK: %w", err)
		}
		fmt.Printf("Private JWK: %s\nPublic JWK: %s\n", privPath, pubPath)
		return nil
	},
}

func init() {
	keygenCmd.Flags().String("out-dir", "keys", "Directory to output key files")
	keygenCmd.Flags().String("type", "", "Key type: rsa|ecc (default: based on category)")
	keygenCmd.Flags().Int("size", 2048, "RSA key size in bits")
	keygenCmd.Flags().String("curve", "P-256", "ECC curve: P-256|P-384|P-521")
	rootCmd.AddCommand(keygenCmd)
}
