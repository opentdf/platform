package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/opentdf/platform/sdk"
)

const (
	benchmarkAttribute     = "https://example.com/attr/attr1/value/value1"
	defaultBenchmarkCount  = 100
	defaultConcurrentCount = 10
)

type connectionConfig struct {
	endpoint     string
	clientID     string
	clientSecret string
}

func addConnectionFlags(fs *flag.FlagSet, cfg *connectionConfig) {
	fs.StringVar(&cfg.endpoint, "endpoint", "https://localhost:8080", "OpenTDF platform endpoint")
	fs.StringVar(&cfg.clientID, "client-id", "opentdf-sdk", "OAuth client ID")
	fs.StringVar(&cfg.clientSecret, "client-secret", "secret", "OAuth client secret")
}

func newClient(cfg connectionConfig) (*sdk.SDK, error) {
	opts := []sdk.Option{sdk.WithClientCredentials(cfg.clientID, cfg.clientSecret, nil)}
	if strings.HasPrefix(cfg.endpoint, "http://") {
		opts = append(opts, sdk.WithInsecurePlaintextConn())
	}
	return sdk.New(cfg.endpoint, opts...)
}

func createBenchmarkTDF(client *sdk.SDK, endpoint string) (string, error) {
	out, err := os.CreateTemp("", "opentdf-benchmark-*.tdf")
	if err != nil {
		return "", err
	}
	path := out.Name()
	cleanup := func() {
		_ = out.Close()
		_ = os.Remove(path)
	}

	_, err = client.CreateTDF(out, strings.NewReader("Hello, World!"),
		sdk.WithDataAttributes(benchmarkAttribute),
		sdk.WithAutoconfigure(false),
		sdk.WithKasInformation(sdk.KASInfo{URL: endpoint}),
	)
	if err != nil {
		cleanup()
		return "", fmt.Errorf("create benchmark TDF: %w", err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func gfmCellEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", "<br>")
}
