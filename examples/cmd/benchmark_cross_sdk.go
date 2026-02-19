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
	"strconv"
	"strings"
	"sync"
	"time"

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

var (
	benchCrossIterations int
	benchCrossSizes      string
)

func init() {
	cmd := &cobra.Command{
		Use:   "benchmark-cross-sdk",
		Short: "Benchmark encrypt/decrypt across Production SDK, Experimental Writer, and WASM",
		Long: `Runs encrypt and decrypt benchmarks for each payload size across three
TDF implementations: the production SDK (CreateTDF/LoadTDF), the experimental
Writer, and the WASM module (via wazero). Results are printed as GFM markdown.`,
		RunE: runBenchmarkCrossSDK,
	}
	cmd.Flags().IntVar(&benchCrossIterations, "iterations", 5, "Iterations per payload size to average") //nolint:mnd
	cmd.Flags().StringVar(&benchCrossSizes, "sizes", "256,1024,16384,65536,262144,1048576", "Comma-separated payload sizes in bytes")
	ExamplesCmd.AddCommand(cmd)
}

// parseSizes splits a comma-separated list of sizes into ints.
func parseSizes(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	sizes := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid size %q: %w", p, err)
		}
		if n <= 0 {
			return nil, fmt.Errorf("size must be positive: %d", n)
		}
		sizes = append(sizes, n)
	}
	return sizes, nil
}

// formatSize formats a byte count as a human-readable string.
func formatSize(n int) string {
	const (
		kb = 1024
		mb = 1024 * 1024
	)
	switch {
	case n >= mb && n%mb == 0:
		return fmt.Sprintf("%d MB", n/mb)
	case n >= kb && n%kb == 0:
		return fmt.Sprintf("%d KB", n/kb)
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// fmtDurationMS formats a duration in ms with one decimal.
func fmtDurationMS(d time.Duration) string {
	return fmt.Sprintf("%.1f ms", float64(d.Microseconds())/1000.0) //nolint:mnd
}

type encryptResult struct {
	size       int
	production time.Duration
	writer     time.Duration
	wasm       time.Duration
	wasmErr    string // non-empty if WASM encrypt failed (e.g. OOM)
}

type decryptResult struct {
	size       int
	production time.Duration
	wasm       time.Duration
	wasmErr    string // non-empty if WASM decrypt failed (e.g. OOM)
}

func runBenchmarkCrossSDK(cmd *cobra.Command, _ []string) error {
	sizes, err := parseSizes(benchCrossSizes)
	if err != nil {
		return err
	}

	// ── Setup: SDK client ────────────────────────────────────────────
	client, err := newSDK()
	if err != nil {
		return fmt.Errorf("create SDK: %w", err)
	}
	defer client.Close()

	// ── Setup: KAS public key for experimental writer ────────────────
	kasKey, err := fetchKASKey()
	if err != nil {
		return fmt.Errorf("fetch KAS key: %w", err)
	}

	// ── Setup: WASM runtime ──────────────────────────────────────────
	fmt.Println("Initializing WASM runtime (wazero)...")
	wrt, err := newWASMRuntime(cmd.Context())
	if err != nil {
		return fmt.Errorf("WASM runtime: %w", err)
	}
	defer func() { wrt.Close() }()
	wasmOK := true // tracks whether WASM runtime is still alive

	// ── Setup: local RSA key pair for WASM encrypt/decrypt ───────────
	kp, err := ocrypto.NewRSAKeyPair(2048) //nolint:mnd
	if err != nil {
		return fmt.Errorf("generate RSA keypair: %w", err)
	}
	wasmPubPEM, err := kp.PublicKeyInPemFormat()
	if err != nil {
		return fmt.Errorf("public key PEM: %w", err)
	}
	wasmPrivPEM, err := kp.PrivateKeyInPemFormat()
	if err != nil {
		return fmt.Errorf("private key PEM: %w", err)
	}

	encResults := make([]encryptResult, len(sizes))
	decResults := make([]decryptResult, len(sizes))

	for i, size := range sizes {
		payload := make([]byte, size)
		if _, err := rand.Read(payload); err != nil {
			return fmt.Errorf("generate payload (%d bytes): %w", size, err)
		}
		fmt.Printf("Benchmarking %s ...\n", formatSize(size))

		// ── Production SDK encrypt ───────────────────────────────────
		prodDur, prodTDF, err := benchProductionEncrypt(client, payload)
		if err != nil {
			return fmt.Errorf("production encrypt (%s): %w", formatSize(size), err)
		}
		encResults[i].size = size
		encResults[i].production = prodDur

		// ── Experimental Writer encrypt ──────────────────────────────
		writerDur, err := benchWriterEncrypt(kasKey, payload)
		if err != nil {
			return fmt.Errorf("writer encrypt (%s): %w", formatSize(size), err)
		}
		encResults[i].writer = writerDur

		// ── WASM encrypt ─────────────────────────────────────────────
		var wasmTDF []byte
		if wasmOK {
			wasmEncDur, tdf, err := benchWASMEncrypt(wrt, wasmPubPEM, payload)
			if err != nil {
				fmt.Printf("  WASM encrypt failed: %v\n", err)
				encResults[i].wasmErr = "OOM"
				// Runtime is likely dead after proc_exit; reinitialize for next size.
				wrt.Close()
				wrt, err = newWASMRuntime(cmd.Context())
				if err != nil {
					fmt.Printf("  WASM runtime reinit failed: %v\n", err)
					wasmOK = false
				}
			} else {
				encResults[i].wasm = wasmEncDur
				wasmTDF = tdf
			}
		} else {
			encResults[i].wasmErr = "N/A"
		}

		// ── Production SDK decrypt ───────────────────────────────────
		prodDecDur, err := benchProductionDecrypt(client, prodTDF)
		if err != nil {
			return fmt.Errorf("production decrypt (%s): %w", formatSize(size), err)
		}
		decResults[i].size = size
		decResults[i].production = prodDecDur

		// ── WASM decrypt ─────────────────────────────────────────────
		if wasmTDF != nil && wasmOK {
			wasmDecDur, err := benchWASMDecrypt(wrt, wasmTDF, wasmPrivPEM)
			if err != nil {
				fmt.Printf("  WASM decrypt failed: %v\n", err)
				decResults[i].wasmErr = "OOM"
				wrt.Close()
				wrt, err = newWASMRuntime(cmd.Context())
				if err != nil {
					fmt.Printf("  WASM runtime reinit failed: %v\n", err)
					wasmOK = false
				}
			} else {
				decResults[i].wasm = wasmDecDur
			}
		} else if wasmTDF == nil {
			decResults[i].wasmErr = "N/A"
		} else {
			decResults[i].wasmErr = "N/A"
		}
	}

	// ── Print results ────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("# Cross-SDK Benchmark Results")
	fmt.Printf("Platform: %s\n", platformEndpoint)
	fmt.Printf("Iterations: %d per size\n", benchCrossIterations)
	fmt.Println()

	fmt.Println("## Encrypt")
	fmt.Println("| Payload | Production SDK | Exp. Writer | WASM |")
	fmt.Println("|---------|---------------|-------------|------|")
	for _, r := range encResults {
		wasmCol := fmtDurationMS(r.wasm)
		if r.wasmErr != "" {
			wasmCol = r.wasmErr
		}
		fmt.Printf("| %s | %s | %s | %s |\n",
			formatSize(r.size), fmtDurationMS(r.production),
			fmtDurationMS(r.writer), wasmCol)
	}

	fmt.Println()
	fmt.Println("## Decrypt")
	fmt.Println("| Payload | Production SDK* | WASM** |")
	fmt.Println("|---------|----------------|--------|")
	for _, r := range decResults {
		wasmCol := fmtDurationMS(r.wasm)
		if r.wasmErr != "" {
			wasmCol = r.wasmErr
		}
		fmt.Printf("| %s | %s | %s |\n",
			formatSize(r.size), fmtDurationMS(r.production), wasmCol)
	}
	fmt.Println("*Production SDK: includes KAS rewrap network latency")
	fmt.Println("**WASM: includes local RSA-OAEP DEK unwrap (no network); in production the host would call KAS for rewrap")

	return nil
}

// ── Individual benchmark functions ───────────────────────────────────

func benchProductionEncrypt(client *sdk.SDK, payload []byte) (time.Duration, []byte, error) {
	baseKasURL := platformEndpoint
	if !strings.HasPrefix(baseKasURL, "http://") && !strings.HasPrefix(baseKasURL, "https://") {
		baseKasURL = "http://" + baseKasURL
	}

	var lastTDF []byte
	var total time.Duration
	for j := 0; j < benchCrossIterations; j++ {
		var tdfBuf bytes.Buffer
		start := time.Now()
		_, err := client.CreateTDF(
			&tdfBuf,
			bytes.NewReader(payload),
			sdk.WithAutoconfigure(false),
			sdk.WithKasInformation(sdk.KASInfo{
				URL:     baseKasURL,
				Default: true,
			}),
			sdk.WithDataAttributes(testAttr),
		)
		total += time.Since(start)
		if err != nil {
			return 0, nil, fmt.Errorf("CreateTDF: %w", err)
		}
		lastTDF = tdfBuf.Bytes()
	}
	return total / time.Duration(benchCrossIterations), lastTDF, nil
}

const writerSegmentSize = 1024 * 1024 // 1 MB — optimal for parallel throughput

func benchWriterEncrypt(kasKey *policy.SimpleKasKey, payload []byte) (time.Duration, error) {
	ctx := context.Background()
	attrs := []*policy.Value{{
		Fqn:       testAttr,
		KasKeys:   []*policy.SimpleKasKey{kasKey},
		Attribute: &policy.Attribute{Namespace: &policy.Namespace{Name: "example.com"}, Fqn: testAttr},
	}}

	var total time.Duration
	for j := 0; j < benchCrossIterations; j++ {
		start := time.Now()

		writer, err := tdf.NewWriter(ctx,
			tdf.WithDefaultKASForWriter(kasKey),
			tdf.WithInitialAttributes(attrs),
		)
		if err != nil {
			return 0, fmt.Errorf("NewWriter: %w", err)
		}

		numSegs := (len(payload) + writerSegmentSize - 1) / writerSegmentSize
		if numSegs == 0 {
			numSegs = 1
		}
		segResults := make([]*tdf.SegmentResult, numSegs)

		var wg sync.WaitGroup
		wg.Add(numSegs)
		for i := 0; i < numSegs; i++ {
			segStart := i * writerSegmentSize
			segEnd := min(segStart+writerSegmentSize, len(payload))
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

		if _, err := writer.Finalize(ctx); err != nil {
			return 0, fmt.Errorf("Finalize: %w", err)
		}

		total += time.Since(start)
	}
	return total / time.Duration(benchCrossIterations), nil
}

func benchWASMEncrypt(wrt *wasmRuntime, pubPEM string, payload []byte) (time.Duration, []byte, error) {
	var lastTDF []byte
	var total time.Duration
	for j := 0; j < benchCrossIterations; j++ {
		start := time.Now()
		tdfBytes, err := wrt.encrypt(pubPEM, "https://kas.local", payload, 0)
		total += time.Since(start)
		if err != nil {
			return 0, nil, fmt.Errorf("wasm encrypt: %w", err)
		}
		lastTDF = tdfBytes
	}
	return total / time.Duration(benchCrossIterations), lastTDF, nil
}

func benchProductionDecrypt(client *sdk.SDK, tdfBytes []byte) (time.Duration, error) {
	var total time.Duration
	for j := 0; j < benchCrossIterations; j++ {
		start := time.Now()
		tdfReader, err := client.LoadTDF(bytes.NewReader(tdfBytes))
		if err != nil {
			return 0, fmt.Errorf("LoadTDF: %w", err)
		}
		if _, err := io.Copy(io.Discard, tdfReader); err != nil {
			return 0, fmt.Errorf("decrypt: %w", err)
		}
		total += time.Since(start)
	}
	return total / time.Duration(benchCrossIterations), nil
}

func benchWASMDecrypt(wrt *wasmRuntime, tdfBytes []byte, privPEM string) (time.Duration, error) {
	var total time.Duration
	for j := 0; j < benchCrossIterations; j++ {
		start := time.Now()
		// Unwrap DEK each iteration — in production the host would call KAS
		// for rewrap; here we do local RSA-OAEP decrypt to measure the full
		// host-side decrypt flow (unwrap + AES-GCM decrypt).
		dek, err := unwrapDEKLocal(tdfBytes, privPEM)
		if err != nil {
			return 0, fmt.Errorf("unwrap DEK: %w", err)
		}
		_, err = wrt.decrypt(tdfBytes, dek)
		total += time.Since(start)
		if err != nil {
			return 0, fmt.Errorf("wasm decrypt: %w", err)
		}
	}
	return total / time.Duration(benchCrossIterations), nil
}

// fetchKASKey retrieves the KAS RSA-2048 public key from the platform.
func fetchKASKey() (*policy.SimpleKasKey, error) {
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

	return &policy.SimpleKasKey{
		KasUri: platformEndpoint,
		KasId:  "id",
		PublicKey: &policy.SimpleKasPublicKey{
			Kid:       resp.Msg.GetKid(),
			Pem:       resp.Msg.GetPublicKey(),
			Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
		},
	}, nil
}
