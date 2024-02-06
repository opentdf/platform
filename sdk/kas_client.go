package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
	kas "github.com/opentdf/backend-go/pkg/access"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type KasClient struct {
	credentials Credentials
	accessToken string
	dpopKey     jwk.Key
}

type requestBody struct {
	Policy            string `json:"policy"`
	KeyType           string `json:"type"`
	KasUrl            string `json:"url"`
	Protocol          string `json:"protocol"`
	WrappedKey        string `json:"wrappedKey"`
	PolicyBinding     string `json:"policyBinding"`
	EncryptedMetaData string `json:"encryptedMetadata"`
}

type requestClaims struct {
	jwt.RegisteredClaims
	RequestBody string `json:"requestBody"`
}

func (client *KasClient) refreshAccessToken() error {
	token, err := client.credentials.GetAccessToken()
	if err != nil {
		return fmt.Errorf("Error getting access token: %w", err)
	}

	client.accessToken = token

	return nil
}

func (client *KasClient) makeRewrapRequest(keyAccess KeyAccess, policy string) (*kas.RewrapResponse, error) {
	rewrapRequest, err := client.getRewrapRequest(keyAccess, policy)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.Dial(keyAccess.KasURL)
	if err != nil {
		return nil, fmt.Errorf("Error connecting to kas: %w", err)
	}

	ctx := context.Background()
	serviceClient := kas.NewAccessServiceClient(conn)

	return serviceClient.Rewrap(ctx, rewrapRequest)
}

func (client *KasClient) Rewrap(keyAccess KeyAccess, policy string) ([]byte, error) {
	if client.accessToken == "" {
		client.refreshAccessToken()
	}

	response, err := client.makeRewrapRequest(keyAccess, policy)

	if err != nil {
		switch status.Code(err) {
		case codes.Unauthenticated:
			client.refreshAccessToken()
			response, err = client.makeRewrapRequest(keyAccess, policy)
			if err != nil {
				return nil, fmt.Errorf("Error making rewrap request: %w", err)
			}
		default:
			return nil, fmt.Errorf("Error making rewrap request: %w", err)
		}
	}

	return response.EntityWrappedKey, nil
}

func (client *KasClient) getRewrapRequest(keyAccess KeyAccess, policy string) (*kas.RewrapRequest, error) {
	requestBody := requestBody{
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
	requestClaims := requestClaims{
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(60 * time.Second)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		string(requestBodyJson),
	}

	signingMethod := jwt.GetSigningMethod(client.dpopKey.Algorithm().String())
	token := jwt.NewWithClaims(signingMethod, requestClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to create jwt: %w", err)
	}

	signedToken, err := token.SignedString(client.dpopKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign the token: %w", err)
	}

	rewrapRequest := kas.RewrapRequest{
		Bearer:             client.accessToken,
		SignedRequestToken: signedToken,
	}
	return &rewrapRequest, nil
}
