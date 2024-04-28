package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/arkavo-org/opentdf-platform/lib/ocrypto"
	"github.com/arkavo-org/opentdf-platform/protocol/go/kas"
	"github.com/arkavo-org/opentdf-platform/sdk/auth"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"google.golang.org/grpc"
)

const (
	secondsPerMinute = 60
)

type KASClient struct {
	accessTokenSource  auth.AccessTokenSource
	dialOptions        []grpc.DialOption
	clientPublicKeyPEM string
	asymDecryption     ocrypto.AsymDecryption
}

// once the backend moves over we should use the same type that the golang backend uses here
type rewrapRequestBody struct {
	KeyAccess       KeyAccess `json:"keyAccess"`
	Policy          string    `json:"policy,omitempty"`
	Algorithm       string    `json:"algorithm,omitempty"`
	ClientPublicKey string    `json:"clientPublicKey"`
	SchemaVersion   string    `json:"schemaVersion,omitempty"`
}

func newKASClient(dialOptions []grpc.DialOption, accessTokenSource auth.AccessTokenSource) (*KASClient, error) {
	rsaKeyPair, err := ocrypto.NewRSAKeyPair(tdf3KeySize)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.NewRSAKeyPair failed: %w", err)
	}

	clientPublicKey, err := rsaKeyPair.PublicKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("ocrypto.PublicKeyInPemFormat failed: %w", err)
	}

	clientPrivateKey, err := rsaKeyPair.PrivateKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("ocrypto.PrivateKeyInPemFormat failed: %w", err)
	}

	asymDecryption, err := ocrypto.NewAsymDecryption(clientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.NewAsymDecryption failed: %w", err)
	}

	return &KASClient{
		accessTokenSource:  accessTokenSource,
		dialOptions:        dialOptions,
		clientPublicKeyPEM: clientPublicKey,
		asymDecryption:     asymDecryption,
	}, nil
}

// there is no connection caching as of now
func (k *KASClient) makeRewrapRequest(keyAccess KeyAccess, policy string) (*kas.RewrapResponse, error) {
	rewrapRequest, err := k.getRewrapRequest(keyAccess, policy)
	if err != nil {
		return nil, err
	}

	grpcAddress, err := getGRPCAddress(keyAccess.KasURL)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.Dial(grpcAddress, k.dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("Error connecting to kas: %w", err)
	}
	defer conn.Close()

	ctx := context.Background()
	serviceClient := kas.NewAccessServiceClient(conn)

	response, err := serviceClient.Rewrap(ctx, rewrapRequest)
	if err != nil {
		return nil, fmt.Errorf("error making rewrap request: %w", err)
	}

	return response, nil
}

func (k *KASClient) unwrap(keyAccess KeyAccess, policy string) ([]byte, error) {
	response, err := k.makeRewrapRequest(keyAccess, policy)
	if err != nil {
		return nil, fmt.Errorf("error making request to kas: %w", err)
	}

	key, err := k.asymDecryption.Decrypt(response.GetEntityWrappedKey())
	if err != nil {
		return nil, fmt.Errorf("error decrypting payload from KAS: %w", err)
	}

	return key, nil
}

func getGRPCAddress(kasURL string) (string, error) {
	parsedURL, err := url.Parse(kasURL)
	if err != nil {
		return "", fmt.Errorf("cannot parse kas url(%s): %w", kasURL, err)
	}

	var address string
	if parsedURL.Port() == "" {
		address = fmt.Sprintf("%s:443", parsedURL.Host)
	} else {
		address = parsedURL.Host
	}

	return address, nil
}

func (k *KASClient) getRewrapRequest(keyAccess KeyAccess, policy string) (*kas.RewrapRequest, error) {
	requestBody := rewrapRequestBody{
		Policy:          policy,
		KeyAccess:       keyAccess,
		ClientPublicKey: k.clientPublicKeyPEM,
	}
	requestBodyJSON, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("Error marshaling request body: %w", err)
	}

	tok, err := jwt.NewBuilder().
		Claim("requestBody", string(requestBodyJSON)).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(secondsPerMinute * time.Second)).
		Build()

	if err != nil {
		return nil, fmt.Errorf("failed to create jwt: %w", err)
	}

	signedToken, err := k.accessTokenSource.MakeToken(func(key jwk.Key) ([]byte, error) {
		signed, err := jwt.Sign(tok, jwt.WithKey(key.Algorithm(), key))
		if err != nil {
			return nil, fmt.Errorf("error signing DPoP token: %w", err)
		}

		return signed, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to sign the token: %w", err)
	}

	//accessToken, err := k.accessTokenSource.AccessToken()
	//if err != nil {
	//	fmt.Printf("warn getting access token: %v", err)
	//}

	rewrapRequest := kas.RewrapRequest{
		//Bearer:             string(accessToken),
		SignedRequestToken: string(signedToken),
	}
	return &rewrapRequest, nil
}

func (k *KASClient) getPublicKey(kasInfo KASInfo) (string, error) {
	req := kas.PublicKeyRequest{}
	grpcAddress, err := getGRPCAddress(kasInfo.URL)
	if err != nil {
		return "", err
	}
	conn, err := grpc.Dial(grpcAddress, k.dialOptions...)
	if err != nil {
		return "", fmt.Errorf("error connecting to grpc service at %s: %w", kasInfo.URL, err)
	}
	defer conn.Close()

	ctx := context.Background()
	serviceClient := kas.NewAccessServiceClient(conn)

	resp, err := serviceClient.PublicKey(ctx, &req)

	if err != nil {
		return "", fmt.Errorf("error making request to KAS: %w", err)
	}

	return resp.GetPublicKey(), nil
}
