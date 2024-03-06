package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	kas "github.com/opentdf/backend-go/pkg/access"
	"github.com/opentdf/platform/sdk/internal/crypto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	secondsPerMinute = 60
)

type KASClient struct {
	accessTokenSource AccessTokenSource
	dialOptions       []grpc.DialOption
}

type AccessToken string

type AccessTokenSource interface {
	GetAccessToken() (AccessToken, error)
	// probably better to use `crypto.AsymDecryption` here than roll our own since this should be
	// more closely linked to what happens in KAS in terms of crypto params
	GetAsymDecryption() crypto.AsymDecryption
	SignToken(jwt.Token) ([]byte, error)
	GetDPoPPublicKeyPEM() string
	RefreshAccessToken() error
}

// once the backend moves over we should use the same type that the golang backend uses here
type rewrapRequestBody struct {
	KeyAccess       KeyAccess `json:"keyAccess"`
	Policy          string    `json:"policy,omitempty"`
	Algorithm       string    `json:"algorithm,omitempty"`
	ClientPublicKey string    `json:"clientPublicKey"`
	SchemaVersion   string    `json:"schemaVersion,omitempty"`
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
		switch status.Code(err) { //nolint:exhaustive // we can only handle authentication
		case codes.Unauthenticated:
			err = k.accessTokenSource.RefreshAccessToken()
			if err != nil {
				return nil, fmt.Errorf("error refreshing access token: %w", err)
			}
			response, err = k.makeRewrapRequest(keyAccess, policy)
			if err != nil {
				return nil, fmt.Errorf("Error making rewrap request: %w", err)
			}
		default:
			return nil, fmt.Errorf("Error making rewrap request: %w", err)
		}
	}

	key, err := k.accessTokenSource.GetAsymDecryption().Decrypt(response.EntityWrappedKey)
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
		ClientPublicKey: k.accessTokenSource.GetDPoPPublicKeyPEM(),
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

	signedToken, err := k.accessTokenSource.SignToken(tok)
	if err != nil {
		return nil, fmt.Errorf("failed to sign the token: %w", err)
	}

	accessToken, err := k.accessTokenSource.GetAccessToken()
	if err != nil {
		return nil, fmt.Errorf("error getting access token: %w", err)
	}

	rewrapRequest := kas.RewrapRequest{
		Bearer:             string(accessToken),
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

	return resp.PublicKey, nil
}
