package virtrusaas

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/opentdf/platform/sdk/httputil"
)

type AcmClient struct {
	client *http.Client
}

func NewAcmClient() *AcmClient {
	return &AcmClient{
		client: httputil.SafeHTTPClient(),
	}
}

type GetContractResponse struct {
	IsOwner bool `json:"isOwner"`
}

func (c *AcmClient) GetContract(policyID string, token string) (*GetContractResponse, error) {
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

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get contract: %s", resp.Status)
	}

	var contractResp GetContractResponse
	if err := json.NewDecoder(resp.Body).Decode(&contractResp); err != nil {
		return nil, err
	}

	return &contractResp, nil
}
