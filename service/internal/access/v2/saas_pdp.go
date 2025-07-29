package access

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk/httputil"
)

// ACM Client for interacting with the ACM API

type AcmClient struct {
	client *http.Client
}

func NewAcmClient() *AcmClient {
	return &AcmClient{
		client: httputil.SafeHTTPClient(),
	}
}

func (c *AcmClient) GetContract(policyID string, token string) (*http.Response, error) {
	reqURL, err := url.Parse("https://api-develop01.develop.virtru.com/acm/api/policies/" + policyID + "/contract")
	if err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: http.MethodGet,
		URL:    reqURL,
		Header: http.Header{
			"Authorization": []string{"Bearer " + token},
		},
	}

	return c.client.Do(req)
}

// SaasPDP implements the Policy Decision Point (PDP) for SaaS applications

type SaasPDP struct {
	acmClient *AcmClient
}

func NewSaasPDP() *SaasPDP {
	return &SaasPDP{
		acmClient: NewAcmClient(),
	}
}

func (p *SaasPDP) GetDecision(
	ctx context.Context,
	entityIdentifier *authzV2.EntityIdentifier,
	action *policy.Action,
	resources []*authzV2.Resource,
) ([]*Decision, bool, error) {

	switch entityIdentifier.GetIdentifier().(type) {
	case *authzV2.EntityIdentifier_Token:
		token := entityIdentifier.GetToken().GetJwt()
		resource := resources[0]

		// https://{OrgID}.kas.virtru.com/attr/cks-acm-adhoc/value/{Policy-UUID}
		policyResourceAttrFQN := resource.GetAttributeValues().GetFqns()[0]
		policyID := policyResourceAttrFQN[strings.LastIndex(policyResourceAttrFQN, "/")+1:]

		// call ACM
		// GET /acm/api/policies/{PolicyID}/contract
		// HEADER Authorization: Bearer {token}
		resp, err := p.acmClient.GetContract(policyID, token)
		if err != nil {
			return nil, false, err
		}
		defer resp.Body.Close()

		decision := ResourceDecision{
			Passed:     resp.StatusCode == http.StatusOK,
			ResourceID: resource.GetEphemeralId(),
		}

		return []*Decision{
			{
				Access:  decision.Passed,
				Results: []ResourceDecision{decision},
			},
		}, decision.Passed, nil

	default:
		return nil, false, errors.New("unsupported entity type")
	}
}
