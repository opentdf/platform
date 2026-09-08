//nolint:forbidigo // We use Println here extensively because we are printing markdown.
package cmd

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/lib/ocrypto"
	kasp "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/kas/kasconnect"
	"github.com/opentdf/platform/protocol/go/policy"

	"github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/sdk/httputil"
	"github.com/spf13/cobra"
)

var (
	payloadSize  int
	segmentChunk int
	testAttr     = "https://example.com/attr/attr1/value/value1"
)

func init() {
	benchmarkCmd := &cobra.Command{
		Use:   "benchmark-chunked-writer",
		Short: "Benchmark chunked TDF writer speed",
		Long:  `Benchmark the chunked TDF writer with configurable payload size.`,
		RunE:  runChunkedWriterBenchmark,
	}
	//nolint: mnd // no magic number, this is just default value for payload size
	benchmarkCmd.Flags().IntVar(&payloadSize, "payload-size", 1024*1024, "Payload size in bytes") // Default 1MB
	//nolint: mnd  // same as above
	benchmarkCmd.Flags().IntVar(&segmentChunk, "segment-chunks", 16*1024, "segment chunks ize") // Default 16 segments
	ExamplesCmd.AddCommand(benchmarkCmd)
}

func runChunkedWriterBenchmark(_ *cobra.Command, _ []string) error {
	payload := make([]byte, payloadSize)
	_, err := rand.Read(payload)
	if err != nil {
		return fmt.Errorf("failed to generate random payload: %w", err)
	}

	http := httputil.SafeHTTPClient()
	fmt.Println("endpoint:", platformEndpoint)
	serviceClient := kasconnect.NewAccessServiceClient(http, platformEndpoint)
	resp, err := serviceClient.PublicKey(context.Background(), connect.NewRequest(&kasp.PublicKeyRequest{Algorithm: string(ocrypto.RSA2048Key)}))
	if err != nil {
		return fmt.Errorf("failed to get public key from KAS: %w", err)
	}

	simpleyKey := &policy.SimpleKasKey{
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
		KasKeys:   []*policy.SimpleKasKey{simpleyKey},
		Attribute: &policy.Attribute{Namespace: &policy.Namespace{Name: "example.com"}, Fqn: testAttr},
	}}

	// The package-level constructor rather than SDK.NewChunkedWriter: this
	// benchmark talks to one KAS whose key it already fetched, so there is
	// nothing for the platform to resolve and no reason to pay for a round trip
	// to it inside the timed section.
	writer, err := sdk.NewChunkedWriter(context.Background(),
		sdk.WithChunkedDefaultKAS(simpleyKey),
		sdk.WithChunkedInitialAttributes(attrs),
		sdk.WithChunkedSegmentIntegrityAlgorithm(sdk.HS256),
	)
	if err != nil {
		return fmt.Errorf("failed to create writer: %w", err)
	}

	segs := len(payload) / segmentChunk
	errs := make([]error, segs)
	wg := sync.WaitGroup{}
	wg.Add(segs)
	start := time.Now()
	for segment := range segs {
		go func() {
			defer wg.Done()
			lo := segment * segmentChunk
			hi := min(lo+segmentChunk, len(payload))
			_, errs[segment] = writer.WriteSegment(context.Background(), segment, payload[lo:hi])
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			return fmt.Errorf("failed to write segment %d: %w", i, err)
		}
	}

	end := time.Now()
	result, err := writer.Finalize(context.Background())
	if err != nil {
		return fmt.Errorf("failed to finalize writer: %w", err)
	}
	totalTime := end.Sub(start)

	fmt.Printf("# Benchmark Chunked TDF Writer Results:\n")
	fmt.Printf("| Metric             | Value         |\n")
	fmt.Printf("|--------------------|--------------|\n")
	fmt.Printf("| Payload Size (B)   | %d |\n", payloadSize)
	fmt.Printf("| Output Size (B)    | %d |\n", len(result.Data))
	fmt.Printf("| Total Time         | %s |\n", totalTime)

	return nil
}
