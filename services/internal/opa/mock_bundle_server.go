package opa

import (
	"fmt"

	sdktest "github.com/open-policy-agent/opa/sdk/test"
	"github.com/opentdf/platform/services/policies"
)

// MockBundleServer is a mock HTTP server that serves a bundle. This should be used for local development only.
type mockBundleServer struct {
	server *sdktest.Server
	config []byte
}

func createMockServer() (*mockBundleServer, error) {
	policy, err := policies.EntitlementsRego.ReadFile("entitlements/entitlements.rego")
	if err != nil {
		return nil, fmt.Errorf("failed to read entitlements policy: %w", err)
	}
	// create a mock HTTP bundle server
	server, err := sdktest.NewServer(sdktest.MockBundle("/bundles/bundle.tar.gz", map[string]string{
		"entitlements.rego": string(policy),
	}))
	if err != nil {
		return nil, fmt.Errorf("failed to create mock bundle server: %w", err)
	}

	config := []byte(fmt.Sprintf(`{
		"services": {
			"test": {
				"url": %q
			}
		},
		"bundles": {
			"test": {
				"resource": "/bundles/bundle.tar.gz"
			}
		},
		"decision_logs": {
  			"console": true
		}
	}`, server.URL()))

	return &mockBundleServer{
		server: server,
		config: config,
	}, nil
}
