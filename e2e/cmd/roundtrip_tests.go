package cmd

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

var RTTestCmd = &cobra.Command{
	Use:   "roundtrip-tests",
	Short: "Run roundtrip tests",
	RunE: func(cmd *cobra.Command, args []string) error {
		testConfig := *(cmd.Context().Value(RootConfigKey).(*TestConfig))
		return runRoundtripTests(&testConfig)
	},
}

func init() {
	E2ECmd.AddCommand(RTTestCmd)
}

var successAttributeSets = [][]string{
	{"https://example.com/attr/language/value/english"},
	{"https://example.com/attr/color/value/red"},
	{"https://example.com/attr/color/value/red", "https://example.com/attr/color/value/green"},
	{"https://example.com/attr/cards/value/jack"},
	{"https://example.com/attr/cards/value/queen"},
	{"https://example.com/attr/language/value/english",
		"https://example.com/attr/color/value/red",
		"https://example.com/attr/color/value/green",
		"https://example.com/attr/cards/value/jack",
		"https://example.com/attr/cards/value/queen"},
}

var failureAttributeSets = [][]string{
	{"https://example.com/attr/language/value/english", "https://example.com/attr/language/value/french"},
	{"https://example.com/attr/color/value/blue"},
	{"https://example.com/attr/color/value/blue", "https://example.com/attr/color/value/green"},
	{"https://example.com/attr/cards/value/king"},
	{"https://example.com/attr/language/value/english",
		"https://example.com/attr/language/value/french",
		"https://example.com/attr/color/value/red",
		"https://example.com/attr/color/value/green",
		"https://example.com/attr/cards/value/queen"},
	{"https://example.com/attr/language/value/english",
		"https://example.com/attr/color/value/blue",
		"https://example.com/attr/color/value/green",
		"https://example.com/attr/cards/value/queen"},
	{"https://example.com/attr/language/value/english",
		"https://example.com/attr/color/value/red",
		"https://example.com/attr/color/value/green",
		"https://example.com/attr/cards/value/king"},
}

func runRoundtripTests(testConfig *TestConfig) error {
	// success tests
	for _, attributes := range successAttributeSets {
		slog.Info("success roundtrip for ", "attributes", attributes)
		err := roundtrip(testConfig, attributes, false)
		if err != nil {
			return err
		}
	}

	// failure tests
	for _, attributes := range failureAttributeSets {
		slog.Info("failutre roundtrip for ", "attributes", attributes)
		err := roundtrip(testConfig, attributes, true)
		if err != nil {
			return err
		}
	}

	return nil
}

func roundtrip(testConfig *TestConfig, attributes []string, failure bool) error {
	const filename = "test-success.tdf"
	const plaintext = "Running a roundtrip test!"
	err := encrypt(testConfig, plaintext, attributes, filename)
	if err != nil {
		return err
	}
	err = decrypt(testConfig, filename, plaintext)
	if failure {
		if err == nil {
			return err
		}
		if !(strings.HasPrefix(err.Error(), "failure on LoadTDF")) {
			return err
		}
	} else {
		if err != nil {
			return err
		}
	}
	return nil
}

func encrypt(testConfig *TestConfig, plaintext string, attributes []string, filename string) error {

	strReader := strings.NewReader(plaintext)

	// Create new offline client
	client, err := sdk.New(testConfig.PlatformEndpoint,
		sdk.WithInsecurePlaintextConn(),
		sdk.WithClientCredentials(testConfig.ClientID,
			testConfig.ClientSecret, nil),
		sdk.WithTokenEndpoint(testConfig.TokenEndpoint),
	)
	if err != nil {
		return err
	}

	tdfFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer tdfFile.Close()

	_, err = client.CreateTDF(tdfFile, strReader,
		sdk.WithDataAttributes(attributes...),
		sdk.WithKasInformation(
			sdk.KASInfo{
				// examples assume insecure http
				URL:       fmt.Sprintf("http://%s", testConfig.PlatformEndpoint),
				PublicKey: "",
			}))
	if err != nil {
		return err
	}

	return nil
}

func decrypt(testConfig *TestConfig, tdfFile string, plaintext string) error {

	// Create new client
	client, err := sdk.New(testConfig.PlatformEndpoint,
		sdk.WithInsecurePlaintextConn(),
		sdk.WithClientCredentials(testConfig.ClientID,
			testConfig.ClientSecret, nil),
		sdk.WithTokenEndpoint(testConfig.TokenEndpoint),
	)
	if err != nil {
		return err
	}
	file, err := os.Open(tdfFile)
	if err != nil {
		return err
	}

	defer file.Close()

	tdfreader, err := client.LoadTDF(file)
	if err != nil {
		return errors.New("failure on LoadTDF: " + err.Error())
	}

	buf := new(strings.Builder)
	_, err = io.Copy(buf, tdfreader)
	if err != nil && err != io.EOF {
		return err
	}

	if buf.String() != plaintext {
		return errors.New("decrypt result (" + buf.String() + ") does not match expected (" + plaintext + ")")
	}

	return nil
}
