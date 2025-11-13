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

	"github.com/opentdf/platform/sdk/experimental/tdf"
	"github.com/opentdf/platform/sdk/httputil"
	"github.com/spf13/cobra"
)

var (
	payloadSize  int
	segmentChunk int
)

func init() {
	benchmarkCmd := &cobra.Command{
		Use:   "benchmark-experimental-writer",
		Short: "Benchmark experimental TDF writer speed",
		Long:  `Benchmark the experimental TDF writer with configurable payload size.`,
		RunE:  runExperimentalWriterBenchmark,
	}
	//nolint: mnd
	benchmarkCmd.Flags().IntVar(&payloadSize, "payload-size", 1024*1024, "Payload size in bytes") // Default 1MB
	//nolint: mnd
	benchmarkCmd.Flags().IntVar(&segmentChunk, "segment-chunks", 16*1024, "segment chunks ize") // Default 16 segments
	ExamplesCmd.AddCommand(benchmarkCmd)
}

func runExperimentalWriterBenchmark(_ *cobra.Command, _ []string) error {
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
	var attrs []*policy.Value

	simpleyKey := &policy.SimpleKasKey{
		KasUri: platformEndpoint,
		KasId:  "id",
		PublicKey: &policy.SimpleKasPublicKey{
			Kid:       resp.Msg.GetKid(),
			Pem:       resp.Msg.GetPublicKey(),
			Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
		},
	}

	attrs = append(attrs, &policy.Value{Fqn: attr, KasKeys: []*policy.SimpleKasKey{simpleyKey}, Attribute: &policy.Attribute{Namespace: &policy.Namespace{Name: "example.com"}, Fqn: attr}})
	writer, err := tdf.NewWriter(context.Background(), tdf.WithDefaultKASForWriter(simpleyKey), tdf.WithInitialAttributes(attrs), tdf.WithSegmentIntegrityAlgorithm(tdf.HS256))
	if err != nil {
		return fmt.Errorf("failed to create writer: %w", err)
	}
	i := 0
	wg := sync.WaitGroup{}
	segs := len(payload) / segmentChunk
	wg.Add(segs)
	start := time.Now()
	for i < segs {
		segment := i
		func() {
			start := i * segmentChunk
			end := min(start+segmentChunk, len(payload))
			_, err = writer.WriteSegment(context.Background(), segment, payload[start:end])
			if err != nil {
				fmt.Println(err)
				panic(err)
			}
			wg.Done()
		}()
		i++
	}
	wg.Wait()

	end := time.Now()
	result, err := writer.Finalize(context.Background())
	if err != nil {
		return fmt.Errorf("failed to finalize writer: %w", err)
	}
	totalTime := end.Sub(start)

	fmt.Printf("# Benchmark Experimental TDF Writer Results:\n")
	fmt.Printf("| Metric             | Value         |\n")
	fmt.Printf("|--------------------|--------------|\n")
	fmt.Printf("| Payload Size (B)   | %d |\n", payloadSize)
	fmt.Printf("| Output Size (B)    | %d |\n", len(result.Data))
	fmt.Printf("| Total Time         | %s |\n", totalTime)

	return nil
}
