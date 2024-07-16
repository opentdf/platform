package cmd

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

var (
	platformEndpoint  string
	clientCredentials string
	tokenEndpoint     string
)

var ExamplesCmd = &cobra.Command{
	Use: "examples",
}

func init() {
	log.SetFlags(log.LstdFlags | log.Llongfile)
	ExamplesCmd.PersistentFlags().StringVarP(&clientCredentials, "creds", "", "opentdf-sdk:secret", "client id:secret credentials")
	ExamplesCmd.PersistentFlags().StringVarP(&platformEndpoint, "platformEndpoint", "e", "localhost:8080", "Platform Endpoint")
	ExamplesCmd.PersistentFlags().StringVarP(&tokenEndpoint, "tokenEndpoint", "t", "http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/token", "OAuth token endpoint")
}

func newSDK() (*sdk.SDK, error) {
	opts := []sdk.Option{sdk.WithInsecurePlaintextConn()}
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
