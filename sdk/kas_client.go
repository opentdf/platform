package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	kas "github.com/opentdf/backend-go/pkg/access"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type Unwrapper interface {
	Unwrap(keyAccess KeyAccess, policy string) ([]byte, error)
	GetRewrappingPublicKey(kasInfo KASInfo) (string, error)
}

type KASClient struct {
	accessTokenSource        AccessTokenSource
	grpcTransportCredentials credentials.TransportCredentials
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
func (client KASClient) makeRewrapRequest(keyAccess KeyAccess, policy string) (*kas.RewrapResponse, error) {
	rewrapRequest, err := client.getRewrapRequest(keyAccess, policy)
	if err != nil {
		return nil, err
	}

	creds := grpc.WithTransportCredentials(client.grpcTransportCredentials)

	grpcAddress, err := getGRPCAddress(keyAccess.KasURL)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.Dial(grpcAddress, creds)
	if err != nil {
		return nil, fmt.Errorf("Error connecting to kas: %w", err)
	}
	defer conn.Close()

	ctx := context.Background()
	serviceClient := kas.NewAccessServiceClient(conn)

	return serviceClient.Rewrap(ctx, rewrapRequest)
}

func (client KASClient) GetKASInfo(keyAccess KeyAccess) (KASInfo, error) {
	return KASInfo{}, nil
}

func (client KASClient) Unwrap(keyAccess KeyAccess, policy string) ([]byte, error) {
	response, err := client.makeRewrapRequest(keyAccess, policy)

	if err != nil {
		switch status.Code(err) {
		case codes.Unauthenticated:
			client.accessTokenSource.RefreshAccessToken()
			response, err = client.makeRewrapRequest(keyAccess, policy)
			if err != nil {
				return nil, fmt.Errorf("Error making rewrap request: %w", err)
			}
		default:
			return nil, fmt.Errorf("Error making rewrap request: %w", err)
		}
	}

	key, err := client.accessTokenSource.GetAsymDecryption().Decrypt(response.EntityWrappedKey)
	if err != nil {
		return nil, fmt.Errorf("error decrypting payload from KAS: %v", err)
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

func (client KASClient) getRewrapRequest(keyAccess KeyAccess, policy string) (*kas.RewrapRequest, error) {
	requestBody := rewrapRequestBody{
		Policy:          policy,
		KeyAccess:       keyAccess,
		ClientPublicKey: client.accessTokenSource.GetDPoPPublicKeyPEM(),
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

	dpopKey := client.accessTokenSource.GetDPoPKey()

	signedToken, err := jwt.Sign(tok, jwt.WithKey(dpopKey.Algorithm(), dpopKey))
	if err != nil {
		return nil, fmt.Errorf("failed to sign the token: %w", err)
	}

	accessToken, err := client.accessTokenSource.GetAccessToken()
	if err != nil {
		return nil, err
	}

	rewrapRequest := kas.RewrapRequest{
		Bearer:             string(accessToken),
		SignedRequestToken: string(signedToken),
	}
	return &rewrapRequest, nil
}

func (client KASClient) GetRewrappingPublicKey(kasInfo KASInfo) (string, error) {
	req := kas.PublicKeyRequest{}
	creds := grpc.WithTransportCredentials(client.grpcTransportCredentials)
	grpcAddress, err := getGRPCAddress(kasInfo.url)
	if err != nil {
		return "", err
	}
	conn, err := grpc.Dial(grpcAddress, creds)
	if err != nil {
		return "", fmt.Errorf("error connecting to grpc service at %s: %w", kasInfo.url, err)
	}
	defer conn.Close()

	ctx := context.Background()
	serviceClient := kas.NewAccessServiceClient(conn)

	resp, err := serviceClient.PublicKey(ctx, &req)

	if err != nil {
		return "", fmt.Errorf("error making request to KAS: %v", err)
	}

	return resp.PublicKey, nil
}
