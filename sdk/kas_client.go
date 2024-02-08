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
	"google.golang.org/grpc/status"
)

type Unwrapper interface {
	Unwrap(keyAccess KeyAccess, policy string) ([]byte, error)
	GetKASPublicKey(kasInfo KASInfo) (string, error)
}

type KasClient struct {
	creds DPoPBoundCredentials
}

type rewrapRequestBody struct {
	Policy            string `json:"policy"`
	KeyType           string `json:"type"`
	KasUrl            string `json:"url"`
	Protocol          string `json:"protocol"`
	WrappedKey        string `json:"wrappedKey"`
	PolicyBinding     string `json:"policyBinding"`
	EncryptedMetaData string `json:"encryptedMetadata"`
}

// TODO: use a single connection and pass in a context. It should come from how the client is using the library
func (client KasClient) makeRewrapRequest(keyAccess KeyAccess, policy string) (*kas.RewrapResponse, error) {
	rewrapRequest, err := client.getRewrapRequest(keyAccess, policy)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.Dial(keyAccess.KasURL)
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
		Policy:            policy,
		KeyType:           keyAccess.KeyType,
		KasUrl:            keyAccess.KasURL,
		Protocol:          keyAccess.Protocol,
		WrappedKey:        keyAccess.WrappedKey,
		PolicyBinding:     keyAccess.PolicyBinding,
		EncryptedMetaData: keyAccess.EncryptedMetadata,
	}
	requestBodyJson, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("Error marshaling request body: %w", err)
	}

	tok, err := jwt.NewBuilder().
		IssuedAt(time.Now()).
		Claim("requestBody", requestBodyJson).
		Expiration(time.Now().Add(60 * time.Second)).
		Build()

	if err != nil {
		return nil, fmt.Errorf("failed to create jwt: %v", err)
	}

	dpopKey, _ := client.creds.GetDPoPKey()

	signedToken, err := jwt.Sign(tok, jwt.WithKey(dpopKey.Algorithm(), dpopKey))
	if err != nil {
		return nil, fmt.Errorf("failed to sign the token: %w", err)
	}

	accessToken, _ := client.creds.GetAccessToken()

	rewrapRequest := kas.RewrapRequest{
		Bearer:             string(accessToken),
		SignedRequestToken: string(signedToken),
	}
	return &rewrapRequest, nil
}

func (client KasClient) GetKASPublicKey(kasInfo KASInfo) (string, error) {
	req := kas.PublicKeyRequest{}
	conn, err := grpc.Dial(kasInfo.url)
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
