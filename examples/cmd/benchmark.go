package cmd

import (
	"bytes"
	"context"
	"fmt"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/resolver"
	"io"
	"sync"
	"time"
)

func init() {
	var benchmarkCmd = &cobra.Command{
		Use:   "benchmark",
		Short: "Decrypt TDF file",
		RunE:  benchmark,
	}
	benchmarkCmd.Flags().StringSliceVarP(&dataAttributes, "data-attributes", "a", []string{"https://example.com/attr/attr1/value/value1"}, "space separated list of data attributes")
	benchmarkCmd.Flags().BoolVar(&nanoFormat, "nano", false, "Output in nanoTDF format")
	benchmarkCmd.Flags().BoolVar(&autoconfigure, "autoconfigure", true, "Use attribute grants to select kases")
	benchmarkCmd.Flags().BoolVar(&noKIDInKAO, "no-kid-in-kao", false, "[deprecated] Disable storing key identifiers in TDF KAOs")
	benchmarkCmd.Flags().BoolVar(&noKIDInNano, "no-kid-in-nano", true, "Disable storing key identifiers in nanoTDF KAS ResourceLocator")
	benchmarkCmd.Flags().StringVarP(&outputName, "output", "o", "sensitive.txt.tdf", "name or path of output file; - for stdout")

	ExamplesCmd.AddCommand(benchmarkCmd)
}

func benchmark(cmd *cobra.Command, args []string) error {
	resolver.SetDefaultScheme("passthrough")
	client, err := newSDK()
	if err != nil {
		return err
	}

	plainBuf := bytes.NewBufferString("small tdf")
	encryptBuf := &bytes.Buffer{}

	cfg, _ := client.NewNanoTDFConfig()
	cfg.SetAttributes(dataAttributes)
	cfg.SetKasURL(fmt.Sprintf("http://%s/kas", platformEndpoint))
	cfg.EnableECDSAPolicyBinding()

	client.CreateNanoTDF(encryptBuf, plainBuf, *cfg)

	var wg sync.WaitGroup
	wg.Add(1000)
	start := time.Now()
	for i := 0; i < 1000; i++ {
		go func() {
			client.ReadNanoTDFContext(context.Background(), io.Discard, bytes.NewReader(encryptBuf.Bytes()))
			wg.Done()
		}()
	}
	wg.Wait()
	end := time.Now()
	elapse := end.Sub(start)
	avg := elapse / 1000
	fmt.Printf("Total Time for 1k calls: %fs\nAverage: %dms\n", elapse.Seconds(), avg.Milliseconds())
	return nil
}
