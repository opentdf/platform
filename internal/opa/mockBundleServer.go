package opa

import (
	"fmt"
	"os"

	sdktest "github.com/open-policy-agent/opa/sdk/test"
)

// MockBundleServer is a mock HTTP server that serves a bundle. This should be used for local development only.
type mockBundleServer struct {
	server *sdktest.Server
	config []byte
}

func createMockServer() (*mockBundleServer, error) {
	policy, err := os.ReadFile("./policies/entitlements/entitlements.rego")
	if err != nil {
		return nil, err
	}
	// create a mock HTTP bundle server
	server, err := sdktest.NewServer(sdktest.MockBundle("/bundles/bundle.tar.gz", map[string]string{
		"entitlements.rego": string(policy),
	}))
	if err != nil {
		return nil, err
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
		}
	}`, server.URL()))

	return &mockBundleServer{
		server: server,
		config: config,
	}, nil
}
