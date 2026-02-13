//nolint:forbidigo // We use Println here extensively because we are printing markdown.
package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
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
	testAttr     = "https://example.com/attr/attr1/value/value1"
)

func init() {
	benchmarkCmd := &cobra.Command{
		Use:   "benchmark-experimental-writer",
		Short: "Benchmark experimental TDF writer speed",
		Long:  `Benchmark the experimental TDF writer with configurable payload size.`,
		RunE:  runExperimentalWriterBenchmark,
	}
	//nolint: mnd // no magic number, this is just default value for payload size
	benchmarkCmd.Flags().IntVar(&payloadSize, "payload-size", 1024*1024, "Payload size in bytes") // Default 1MB
	//nolint: mnd  // same as above
	benchmarkCmd.Flags().IntVar(&segmentChunk, "segment-chunks", 16*1024, "segment chunk size") // Default 16KB
	ExamplesCmd.AddCommand(benchmarkCmd)
}

func runExperimentalWriterBenchmark(_ *cobra.Command, _ []string) error {
	payload := make([]byte, payloadSize)
	_, err := rand.Read(payload)
	if err != nil {
		return fmt.Errorf("failed to generate random payload: %w", err)
	}

	var httpClient *http.Client
	if insecureSkipVerify {
		httpClient = httputil.SafeHTTPClientWithTLSConfig(&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // user-requested flag
	} else {
		httpClient = httputil.SafeHTTPClient()
	}
	fmt.Println("endpoint:", platformEndpoint)
	serviceClient := kasconnect.NewAccessServiceClient(httpClient, platformEndpoint)
	resp, err := serviceClient.PublicKey(context.Background(), connect.NewRequest(&kasp.PublicKeyRequest{Algorithm: string(ocrypto.RSA2048Key)}))
	if err != nil {
		return fmt.Errorf("failed to get public key from KAS: %w", err)
	}
	var attrs []*policy.Value

	simpleKey := &policy.SimpleKasKey{
		KasUri: platformEndpoint,
		KasId:  "id",
		PublicKey: &policy.SimpleKasPublicKey{
			Kid:       resp.Msg.GetKid(),
			Pem:       resp.Msg.GetPublicKey(),
			Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
		},
	}

	attrs = append(attrs, &policy.Value{Fqn: testAttr, KasKeys: []*policy.SimpleKasKey{simpleKey}, Attribute: &policy.Attribute{Namespace: &policy.Namespace{Name: "example.com"}, Fqn: testAttr}})
	writer, err := tdf.NewWriter(context.Background(), tdf.WithDefaultKASForWriter(simpleKey), tdf.WithInitialAttributes(attrs), tdf.WithSegmentIntegrityAlgorithm(tdf.HS256))
	if err != nil {
		return fmt.Errorf("failed to create writer: %w", err)
	}
	segs := (len(payload) + segmentChunk - 1) / segmentChunk
	segResults := make([]*tdf.SegmentResult, segs)
	wg := sync.WaitGroup{}
	wg.Add(segs)
	start := time.Now()
	for i := 0; i < segs; i++ {
		segStart := i * segmentChunk
		segEnd := min(segStart+segmentChunk, len(payload))
		// Copy the chunk: EncryptInPlace overwrites the input buffer and
		// appends a 16-byte auth tag, which would corrupt adjacent segments.
		chunk := make([]byte, segEnd-segStart)
		copy(chunk, payload[segStart:segEnd])
		go func(index int, data []byte) {
			defer wg.Done()
			sr, serr := writer.WriteSegment(context.Background(), index, data)
			if serr != nil {
				panic(serr)
			}
			segResults[index] = sr
		}(i, chunk)
	}
	wg.Wait()

	end := time.Now()
	result, err := writer.Finalize(context.Background())
	if err != nil {
		return fmt.Errorf("failed to finalize writer: %w", err)
	}
	totalTime := end.Sub(start)

	// Assemble the complete TDF: segment data (in order) + finalize data
	var tdfBuf bytes.Buffer
	for i, sr := range segResults {
		if _, err := io.Copy(&tdfBuf, sr.TDFData); err != nil {
			return fmt.Errorf("failed to read segment %d TDF data: %w", i, err)
		}
	}
	tdfBuf.Write(result.Data)

	outPath := "/tmp/benchmark-experimental.tdf"
	if err := os.WriteFile(outPath, tdfBuf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("failed to write TDF: %w", err)
	}

	fmt.Printf("# Benchmark Experimental TDF Writer Results:\n")
	fmt.Printf("| Metric             | Value         |\n")
	fmt.Printf("|--------------------|--------------|\n")
	fmt.Printf("| Payload Size (B)   | %d |\n", payloadSize)
	fmt.Printf("| Output Size (B)    | %d |\n", tdfBuf.Len())
	fmt.Printf("| Total Time         | %s |\n", totalTime)
	fmt.Printf("| TDF saved to       | %s |\n", outPath)

	// Decrypt with production SDK to verify interoperability
	s, err := newSDK()
	if err != nil {
		return fmt.Errorf("failed to create SDK: %w", err)
	}
	defer s.Close()
	tdfReader, err := s.LoadTDF(bytes.NewReader(tdfBuf.Bytes()))
	if err != nil {
		return fmt.Errorf("failed to load TDF with production SDK: %w", err)
	}
	var decrypted bytes.Buffer
	if _, err = io.Copy(&decrypted, tdfReader); err != nil {
		return fmt.Errorf("failed to decrypt TDF with production SDK: %w", err)
	}

	if bytes.Equal(payload, decrypted.Bytes()) {
		fmt.Println("| Decrypt Verify     | PASS - roundtrip matches |")
	} else {
		fmt.Printf("| Decrypt Verify     | FAIL - payload %d bytes, decrypted %d bytes |\n", len(payload), decrypted.Len())
	}

	return nil
}
