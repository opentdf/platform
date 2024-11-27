package cmd

import (
	"fmt"
	"log"
	"os"
	"strings"

	"google.golang.org/grpc/resolver"

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
	f.StringVarP(&platformEndpoint, "platformEndpoint", "e", "localhost:8080", "Platform Endpoint")
	f.StringVarP(&tokenEndpoint, "tokenEndpoint", "t", "http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/token", "OAuth token endpoint")
	f.BoolVar(&storeCollectionHeaders, "storeCollectionHeaders", false, "Store collection headers")
	f.BoolVar(&insecurePlaintextConn, "insecurePlaintextConn", false, "Use insecure plaintext connection")
	f.BoolVar(&insecureSkipVerify, "insecureSkipVerify", false, "Skip server certificate verification")
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
			return nil, fmt.Errorf("invalid client id/secret pair")
		}
		opts = append(opts, sdk.WithClientCredentials(clientCredentials[:i], clientCredentials[i+1:], nil))
	}
	if tokenEndpoint != "" {
		opts = append(opts, sdk.WithTokenEndpoint(tokenEndpoint))
	}
	return sdk.New(platformEndpoint, opts...)
}

func Execute() {
	if err := ExamplesCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
