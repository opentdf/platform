package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/spf13/cobra"
)

const clientPrivateKeyJwtCmdShort = "Request OAuth2 token using JWT client assertion (private key in JWK) and optional DPoP"
const clientPrivateKeyJwtCmdLong string = clientPrivateKeyJwtCmdShort + `

Common token uris:
  - Ping: https://localhost:9031/as/token.oauth2
`

var clientPrivateKeyJwtCmd = &cobra.Command{
	Use:   "client-private-key-jwt",
	Short: clientPrivateKeyJwtCmdShort,
	Long:  clientPrivateKeyJwtCmdLong,
	RunE: func(cmd *cobra.Command, args []string) error {
		clientID, _ := cmd.Flags().GetString("client-id")
		tokenURL, _ := cmd.Flags().GetString("token-url")
		jwkFilePath, _ := cmd.Flags().GetString("jwk")
		useDPoP, _ := cmd.Flags().GetBool("dpop")

		if tokenURL == "" {
			return fmt.Errorf("Token url must not be empty. See help for more information.")
		}

		fmt.Println("➡️  Generating client assertion JWT...")
		clientAssertion, err := createClientAssertion(clientID, tokenURL, jwkFilePath)
		if err != nil {
			return fmt.Errorf("Error creating client assertion: %w", err)
		}

		data := url.Values{}
		data.Set("grant_type", "client_credentials")
		data.Set("client_id", clientID)
		data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		data.Set("client_assertion", clientAssertion)

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}

		fmt.Printf("🚀 Sending request to %s...\n", tokenURL)
		req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
		if err != nil {
			return fmt.Errorf("Error creating request: %w", err)
		}
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		// DPoP support (ephemeral key only if --dpop is set)
		if useDPoP {
			tmpKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return fmt.Errorf("Error generating temporary DPoP key: %w", err)
			}
			dpopJWT, err := createDPoPProofFromKey(tmpKey, tokenURL, "POST")
			if err != nil {
				return fmt.Errorf("Error creating DPoP proof: %w", err)
			}
			req.Header.Add("DPoP", dpopJWT)
			fmt.Printf("🪪 DPoP proof added (ephemeral key)\n")
		}

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("Error sending request: %w", err)
		}
		defer resp.Body.Close()

		fmt.Printf("\n✅ Status: %s\n", resp.Status)
		fmt.Println("📄 Response Body:")
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("Error reading response body: %w", err)
		}
		fmt.Println(string(body))
		return nil
	},
}

func init() {
	clientPrivateKeyJwtCmd.Flags().String("client-id", "opentdf", "OAuth2 client ID")
	clientPrivateKeyJwtCmd.Flags().String("token-url", "", "OAuth2 token endpoint URL")
	clientPrivateKeyJwtCmd.Flags().String("jwk", "./keys/client-credentials-private.jwk", "Path to JWK private key file")
	clientPrivateKeyJwtCmd.Flags().Bool("dpop", true, "Use DPoP (ephemeral EC P-256 key)")
	ExamplesCmd.AddCommand(clientPrivateKeyJwtCmd)
}

// createClientAssertion reads a JWK, builds claims, and returns a signed JWT string.
func createClientAssertion(clientID, audience, jwkPath string) (string, error) {
	// Read the JWK file content
	jwkBytes, err := os.ReadFile(jwkPath)
	if err != nil {
		return "", fmt.Errorf("failed to read JWK file: %w", err)
	}

	// Parse the JWK to get the RSA private key and kid
	var jwkData map[string]interface{}
	if err := json.Unmarshal(jwkBytes, &jwkData); err != nil {
		return "", fmt.Errorf("failed to unmarshal JWK: %w", err)
	}
	kid, _ := jwkData["kid"].(string)
	if kid == "" {
		return "", fmt.Errorf("JWK does not have a 'kid' set; this is required by the IDP")
	}
	fmt.Printf("Using JWK with kid: %s\n", kid)

	keyset, err := jwk.Parse(jwkBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse JWK: %w", err)
	}
	if keyset.Len() == 0 {
		return "", fmt.Errorf("no keys found in JWK file")
	}
	key, ok := keyset.Key(0)
	if !ok {
		return "", fmt.Errorf("failed to get key from JWK set")
	}
	var rawKey interface{}
	if err := key.Raw(&rawKey); err != nil {
		return "", fmt.Errorf("failed to get raw RSA key: %w", err)
	}
	rsaPriv, ok := rawKey.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("JWK is not an RSA private key")
	}

	// Build claims with aud as a string
	now := time.Now()
	exp := now.Add(5 * time.Minute)
	claims := jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"jti": fmt.Sprintf("jti-%d", now.UnixNano()),
		"iat": now.Unix(),
		"exp": exp.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	signedJWT, err := token.SignedString(rsaPriv)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	fmt.Printf("\n🔑 JWT (paste at https://jwt.io to inspect):\n%s\n\n", signedJWT)
	return signedJWT, nil
}

// createDPoPProof generates a DPoP proof JWT for the given URL and method using the provided EC private key (PEM).
func createDPoPProof(privKeyPath, htu, htm string) (string, error) {
	pemBytes, err := os.ReadFile(privKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read DPoP private key: %w", err)
	}
	privKey, err := jwt.ParseECPrivateKeyFromPEM(pemBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse EC private key: %w", err)
	}
	return createDPoPProofFromKey(privKey, htu, htm)
}

// createDPoPProofFromKey generates a DPoP proof JWT using an in-memory EC private key.
func createDPoPProofFromKey(privKey *ecdsa.PrivateKey, htu, htm string) (string, error) {
	now := time.Now().Unix()
	jti := fmt.Sprintf("jti-%d", now)
	claims := jwt.MapClaims{
		"htu": htu,
		"htm": strings.ToUpper(htm),
		"jti": jti,
		"iat": now,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"

	// Add public JWK to header as required by DPoP spec
	pubJWK, err := jwk.PublicKeyOf(privKey)
	if err != nil {
		return "", fmt.Errorf("failed to create JWK from EC key: %w", err)
	}
	pubJWKJSON, err := json.Marshal(pubJWK)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWK: %w", err)
	}
	var pubJWKMap map[string]interface{}
	if err := json.Unmarshal(pubJWKJSON, &pubJWKMap); err != nil {
		return "", fmt.Errorf("failed to unmarshal JWK: %w", err)
	}
	token.Header["jwk"] = pubJWKMap

	dpopJWT, err := token.SignedString(privKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign DPoP JWT: %w", err)
	}
	return dpopJWT, nil
}

// generateDPoPKey generates a new EC P-256 DPoP key and saves it to the given PEM file path.
func generateDPoPKey(path string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate EC key: %w", err)
	}
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal EC key: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
		return fmt.Errorf("failed to encode PEM: %w", err)
	}
	fmt.Printf("DPoP EC P-256 private key written to %s\n", path)
	return nil
}
