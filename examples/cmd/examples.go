package cmd

import (
	"errors"
	"log"
	"strings"

	"google.golang.org/grpc/resolver"

	"github.com/opentdf/platform/examples/cmd/authpkce"
	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

var (
	platformEndpoint       string
	clientCredentials      string
	tokenEndpoint          string
	storeCollectionHeaders bool
	insecurePlaintextConn  bool
	insecureSkipVerify     bool
)

var ExamplesCmd = &cobra.Command{
	Use: "examples",
}

func init() {
	log.SetFlags(log.LstdFlags | log.Llongfile)
	f := ExamplesCmd.PersistentFlags()
	f.StringVarP(&clientCredentials, "creds", "", "opentdf-sdk:secret", "client id:secret credentials")
	f.StringVarP(&platformEndpoint, "platformEndpoint", "e", "http://localhost:8080", "Platform Endpoint")
	f.StringVarP(&tokenEndpoint, "tokenEndpoint", "t", "http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/token", "OAuth token endpoint")
	f.BoolVar(&storeCollectionHeaders, "storeCollectionHeaders", false, "Store collection headers")
	f.BoolVar(&insecurePlaintextConn, "insecurePlaintextConn", false, "Use insecure plaintext connection")
	f.BoolVar(&insecureSkipVerify, "insecureSkipVerify", false, "Skip server certificate verification")
	ExamplesCmd.AddCommand(authpkce.Cmd)
}

func newSDK() (*sdk.SDK, error) {
	resolver.SetDefaultScheme("passthrough")
	opts := []sdk.Option{}
	if insecurePlaintextConn {
		opts = append(opts, sdk.WithInsecurePlaintextConn())
	}
	if insecureSkipVerify {
		opts = append(opts, sdk.WithInsecureSkipVerifyConn())
	}
	if storeCollectionHeaders {
		opts = append(opts, sdk.WithStoreCollectionHeaders())
	}
	if clientCredentials != "" {
		i := strings.Index(clientCredentials, ":")
		if i < 0 {
			return nil, errors.New("invalid client id/secret pair")
		}
		opts = append(opts, sdk.WithClientCredentials(clientCredentials[:i], clientCredentials[i+1:], nil))
	}
	if tokenEndpoint != "" {
		opts = append(opts, sdk.WithTokenEndpoint(tokenEndpoint))
	}
	if noKIDInKAO {
		opts = append(opts, sdk.WithNoKIDInKAO())
	}
	// double negative always gets me
	if !noKIDInNano {
		opts = append(opts, sdk.WithNoKIDInNano())
	}
	return sdk.New(platformEndpoint, opts...)
}

func Execute() {
	if err := ExamplesCmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
	}
}
