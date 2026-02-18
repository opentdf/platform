//nolint:forbidigo // We use Println here because we are printing results.
package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/lib/ocrypto"
	kasp "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/kas/kasconnect"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/sdk/experimental/tdf"
	"github.com/opentdf/platform/sdk/httputil"
	"github.com/spf13/cobra"
)

var crossSDKPayloadSize int

func init() {
	cmd := &cobra.Command{
		Use:   "cross-sdk-verify",
		Short: "Verify cross-SDK TDF encrypt/decrypt compatibility",
		Long: `Creates TDFs using both the production SDK (CreateTDF) and the
experimental Writer, then decrypts each with the production SDK (LoadTDF)
to verify format compatibility. Requires a running platform.`,
		RunE: runCrossSDKVerify,
	}
	cmd.Flags().IntVar(&crossSDKPayloadSize, "payload-size", 256, "Payload size in bytes") //nolint:mnd // default value
	ExamplesCmd.AddCommand(cmd)
}

func runCrossSDKVerify(cmd *cobra.Command, _ []string) error {
	// Generate random payload
	payload := make([]byte, crossSDKPayloadSize)
	if _, err := rand.Read(payload); err != nil {
		return fmt.Errorf("generate payload: %w", err)
	}

	client, err := newSDK()
	if err != nil {
		return fmt.Errorf("create SDK: %w", err)
	}
	defer client.Close()

	fmt.Println("# Cross-SDK Verification")
	fmt.Printf("Platform: %s\n", platformEndpoint)
	fmt.Printf("Payload:  %d bytes\n\n", len(payload))

	// ── Test 1: Production SDK CreateTDF → LoadTDF ───────────────────
	fmt.Print("1. Production CreateTDF → LoadTDF ... ")
	if err := verifyProductionRoundTrip(client, payload); err != nil {
		fmt.Printf("FAIL: %v\n", err)
	} else {
		fmt.Println("PASS")
	}

	// ── Test 2: Experimental Writer → Production LoadTDF ─────────────
	fmt.Print("2. Experimental Writer → Production LoadTDF ... ")
	if err := verifyExperimentalToProduction(cmd, client, payload); err != nil {
		fmt.Printf("FAIL: %v\n", err)
	} else {
		fmt.Println("PASS")
	}

	// ── Test 3: Experimental Writer (multi-segment) → Production LoadTDF
	fmt.Print("3. Experimental Writer (multi-segment) → Production LoadTDF ... ")
	if err := verifyExperimentalMultiSegToProduction(cmd, client, payload); err != nil {
		fmt.Printf("FAIL: %v\n", err)
	} else {
		fmt.Println("PASS")
	}

	// ── Tests 4-5: WASM decrypt via wazero ───────────────────────────
	fmt.Println("\nInitializing WASM runtime (wazero)...")
	wrt, err := newWASMRuntime(cmd.Context())
	if err != nil {
		fmt.Printf("WASM runtime init: %v\n", err)
		return nil // non-fatal — WASM tests are skipped
	}
	defer wrt.Close()

	// ── Test 4: Experimental Writer → WASM decrypt (wazero) ──────────
	fmt.Print("4. Experimental Writer → WASM decrypt (wazero) ... ")
	if err := verifyWriterToWASM(wrt, payload); err != nil {
		fmt.Printf("FAIL: %v\n", err)
	} else {
		fmt.Println("PASS")
	}

	// ── Test 5: Experimental Writer (multi-segment) → WASM decrypt ───
	fmt.Print("5. Experimental Writer (multi-segment) → WASM decrypt (wazero) ... ")
	if err := verifyWriterMultiSegToWASM(wrt, payload); err != nil {
		fmt.Printf("FAIL: %v\n", err)
	} else {
		fmt.Println("PASS")
	}

	return nil
}

// verifyProductionRoundTrip creates a TDF with the production SDK and decrypts it.
func verifyProductionRoundTrip(client *sdk.SDK, payload []byte) error {
	baseKasURL := platformEndpoint
	if !strings.HasPrefix(baseKasURL, "http://") && !strings.HasPrefix(baseKasURL, "https://") {
		baseKasURL = "http://" + baseKasURL
	}

	var tdfBuf bytes.Buffer
	_, err := client.CreateTDF(
		&tdfBuf,
		bytes.NewReader(payload),
		sdk.WithAutoconfigure(false),
		sdk.WithKasInformation(sdk.KASInfo{
			URL:     baseKasURL,
			Default: true,
		}),
		sdk.WithDataAttributes("https://example.com/attr/attr1/value/value1"),
	)
	if err != nil {
		return fmt.Errorf("CreateTDF: %w", err)
	}

	return verifyDecrypt(client, tdfBuf.Bytes(), payload)
}

// verifyExperimentalToProduction creates a single-segment TDF with the
// experimental Writer and decrypts with the production SDK.
func verifyExperimentalToProduction(_ *cobra.Command, client *sdk.SDK, payload []byte) error {
	tdfBytes, err := createExperimentalTDF(payload, 0)
	if err != nil {
		return err
	}
	return verifyDecrypt(client, tdfBytes, payload)
}

// verifyExperimentalMultiSegToProduction creates a multi-segment TDF with
// the experimental Writer and decrypts with the production SDK.
func verifyExperimentalMultiSegToProduction(_ *cobra.Command, client *sdk.SDK, payload []byte) error {
	segSize := len(payload) / 3 //nolint:mnd // split into ~3 segments
	if segSize < 1 {
		segSize = 1
	}
	tdfBytes, err := createExperimentalTDF(payload, segSize)
	if err != nil {
		return err
	}
	return verifyDecrypt(client, tdfBytes, payload)
}

// createExperimentalTDF builds a TDF using the experimental Writer. If
// segmentSize <= 0 the entire payload is one segment.
func createExperimentalTDF(payload []byte, segmentSize int) ([]byte, error) {
	var httpClient *http.Client
	if insecureSkipVerify {
		httpClient = httputil.SafeHTTPClientWithTLSConfig(&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // user-requested flag
	} else {
		httpClient = httputil.SafeHTTPClient()
	}

	serviceClient := kasconnect.NewAccessServiceClient(httpClient, platformEndpoint)
	resp, err := serviceClient.PublicKey(context.Background(), connect.NewRequest(&kasp.PublicKeyRequest{Algorithm: string(ocrypto.RSA2048Key)}))
	if err != nil {
		return nil, fmt.Errorf("get KAS public key: %w", err)
	}

	simpleKey := &policy.SimpleKasKey{
		KasUri: platformEndpoint,
		KasId:  "id",
		PublicKey: &policy.SimpleKasPublicKey{
			Kid:       resp.Msg.GetKid(),
			Pem:       resp.Msg.GetPublicKey(),
			Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
		},
	}
	attrs := []*policy.Value{{
		Fqn:       testAttr,
		KasKeys:   []*policy.SimpleKasKey{simpleKey},
		Attribute: &policy.Attribute{Namespace: &policy.Namespace{Name: "example.com"}, Fqn: testAttr},
	}}

	ctx := context.Background()
	writer, err := tdf.NewWriter(ctx,
		tdf.WithDefaultKASForWriter(simpleKey),
		tdf.WithInitialAttributes(attrs),
	)
	if err != nil {
		return nil, fmt.Errorf("NewWriter: %w", err)
	}

	// Determine segments
	if segmentSize <= 0 || segmentSize >= len(payload) {
		segmentSize = len(payload)
	}
	numSegs := (len(payload) + segmentSize - 1) / segmentSize
	if numSegs == 0 {
		numSegs = 1
	}

	segResults := make([]*tdf.SegmentResult, numSegs)
	var wg sync.WaitGroup
	wg.Add(numSegs)
	for i := 0; i < numSegs; i++ {
		segStart := i * segmentSize
		segEnd := min(segStart+segmentSize, len(payload))
		chunk := make([]byte, segEnd-segStart)
		copy(chunk, payload[segStart:segEnd])
		go func(index int, data []byte) {
			defer wg.Done()
			sr, serr := writer.WriteSegment(ctx, index, data)
			if serr != nil {
				panic(serr)
			}
			segResults[index] = sr
		}(i, chunk)
	}
	wg.Wait()

	result, err := writer.Finalize(ctx)
	if err != nil {
		return nil, fmt.Errorf("Finalize: %w", err)
	}

	var tdfBuf bytes.Buffer
	for i, sr := range segResults {
		if _, err := io.Copy(&tdfBuf, sr.TDFData); err != nil {
			return nil, fmt.Errorf("read segment %d: %w", i, err)
		}
	}
	tdfBuf.Write(result.Data)
	return tdfBuf.Bytes(), nil
}

// verifyDecrypt decrypts a TDF with the production SDK and compares the result.
func verifyDecrypt(client *sdk.SDK, tdfBytes, expected []byte) error {
	tdfReader, err := client.LoadTDF(bytes.NewReader(tdfBytes))
	if err != nil {
		return fmt.Errorf("LoadTDF: %w", err)
	}
	var decrypted bytes.Buffer
	if _, err = io.Copy(&decrypted, tdfReader); err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	if !bytes.Equal(decrypted.Bytes(), expected) {
		return fmt.Errorf("plaintext mismatch: got %d bytes, want %d bytes", decrypted.Len(), len(expected))
	}
	return nil
}
