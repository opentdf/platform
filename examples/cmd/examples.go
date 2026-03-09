package cmd

import (
	"errors"
	"log"
	"strings"

	"google.golang.org/grpc/resolver"

	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

var (
	platformEndpoint      string
	clientCredentials     string
	insecurePlaintextConn bool
	insecureSkipVerify    bool
)

var ExamplesCmd = &cobra.Command{
	Use: "examples",
}

func init() {
	log.SetFlags(log.LstdFlags | log.Llongfile)
	f := ExamplesCmd.PersistentFlags()
	f.StringVarP(&clientCredentials, "creds", "", "opentdf-sdk:secret", "client id:secret credentials")
	f.StringVarP(&platformEndpoint, "platformEndpoint", "e", "https://localhost:8080", "Platform Endpoint")
	f.BoolVar(&insecurePlaintextConn, "insecurePlaintextConn", false, "Use insecure plaintext connection")
	f.BoolVar(&insecureSkipVerify, "insecureSkipVerify", false, "Skip server certificate verification")
}

func newSDK() (*sdk.SDK, error) {
	resolver.SetDefaultScheme("passthrough")
	opts := []sdk.Option{}
	if insecurePlaintextConn {
		platformEndpoint = strings.Replace(platformEndpoint, "https://", "http://", 1)
		opts = append(opts, sdk.WithInsecurePlaintextConn())
	}
	if insecureSkipVerify {
		opts = append(opts, sdk.WithInsecureSkipVerifyConn())
	}
	if clientCredentials != "" {
		i := strings.Index(clientCredentials, ":")
		if i < 0 {
			return nil, errors.New("invalid client id/secret pair")
		}
		opts = append(opts, sdk.WithClientCredentials(clientCredentials[:i], clientCredentials[i+1:], nil))
	}
	if noKIDInKAO {
		opts = append(opts, sdk.WithNoKIDInKAO())
	}
	return sdk.New(platformEndpoint, opts...)
}

func Execute() {
	if err := ExamplesCmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
	}
}
