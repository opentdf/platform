package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	kas "github.com/opentdf/backend-go/pkg/access"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type Unwrapper interface {
	Unwrap(keyAccess KeyAccess, policy string) ([]byte, error)
	GetKASPublicKey(kasInfo KASInfo) (string, error)
}

type KasClient struct {
	creds AccessTokenSource
}

// TODO: use the same type that the golang backend uses here
type rewrapRequestBody struct {
	KeyAccess       KeyAccess `json:"keyAccess"`
	Policy          string    `json:"policy,omitempty"`
	Algorithm       string    `json:"algorithm,omitempty"`
	ClientPublicKey string    `json:"clientPublicKey"`
	SchemaVersion   string    `json:"schemaVersion,omitempty"`
}

// TODO: use a single connection and pass in a context. It should come from how the client is using the library
func (client KasClient) makeRewrapRequest(keyAccess KeyAccess, policy string) (*kas.RewrapResponse, error) {
	rewrapRequest, err := client.getRewrapRequest(keyAccess, policy)
	if err != nil {
		return nil, err
	}
	// TODO: figure out how to use the right kind credentials for testing or get KAS running over SSL in test
	creds := grpc.WithTransportCredentials(insecure.NewCredentials())
	conn, err := grpc.Dial("localhost:9000", creds)
	if err != nil {
		return nil, fmt.Errorf("Error connecting to kas: %w", err)
	}
	defer conn.Close()

	ctx := context.Background()
	serviceClient := kas.NewAccessServiceClient(conn)

	return serviceClient.Rewrap(ctx, rewrapRequest)
}

func (client KasClient) GetKASInfo(keyAccess KeyAccess) (KASInfo, error) {
	return KASInfo{}, nil
}

func (client KasClient) Unwrap(keyAccess KeyAccess, policy string) ([]byte, error) {
	response, err := client.makeRewrapRequest(keyAccess, policy)

	if err != nil {
		switch status.Code(err) {
		case codes.Unauthenticated:
			client.creds.RefreshAccessToken()
			response, err = client.makeRewrapRequest(keyAccess, policy)
			if err != nil {
				return nil, fmt.Errorf("Error making rewrap request: %w", err)
			}
		default:
			return nil, fmt.Errorf("Error making rewrap request: %w", err)
		}
	}

	key, err := client.creds.GetAsymDecryption().Decrypt(response.EntityWrappedKey)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func (client KasClient) getRewrapRequest(keyAccess KeyAccess, policy string) (*kas.RewrapRequest, error) {

	requestBody := rewrapRequestBody{
		Policy:          policy,
		KeyAccess:       keyAccess,
		ClientPublicKey: client.creds.GetDPoPPublicKeyPEM(),
	}

	requestBodyJson, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("Error marshaling request body: %w", err)
	}

	tok, err := jwt.NewBuilder().
		Claim("requestBody", string(requestBodyJson)).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(60 * time.Second)).
		Build()

	if err != nil {
		return nil, fmt.Errorf("failed to create jwt: %v", err)
	}

	dpopKey := client.creds.GetDPoPKey()

	signedToken, err := jwt.Sign(tok, jwt.WithKey(dpopKey.Algorithm(), dpopKey))
	if err != nil {
		return nil, fmt.Errorf("failed to sign the token: %w", err)
	}

	accessToken, err := client.creds.GetAccessToken()
	if err != nil {
		return nil, err
	}

	rewrapRequest := kas.RewrapRequest{
		Bearer:             string(accessToken),
		SignedRequestToken: string(signedToken),
	}
	return &rewrapRequest, nil
}

func (client KasClient) GetKASPublicKey(kasInfo KASInfo) (string, error) {
	req := kas.PublicKeyRequest{}
	creds := grpc.WithTransportCredentials(insecure.NewCredentials())
	conn, err := grpc.Dial("localhost:9000", creds)
	if err != nil {
		return "", fmt.Errorf("error connecting to grpc service at %s: %w", kasInfo.url, err)
	}
	defer conn.Close()

	ctx := context.Background()
	serviceClient := kas.NewAccessServiceClient(conn)

	resp, err := serviceClient.PublicKey(ctx, &req)

	if err != nil {
		return "", fmt.Errorf("error making request to Kas: %v", err)
	}

	return resp.PublicKey, nil
}
