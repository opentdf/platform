package cmd

import (
	"bytes"
	"fmt"
	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
	"strconv"
	"strings"
	"sync"
	"time"
)

var nanoPerfCmd = &cobra.Command{
	Use:   "nano-perf",
	Short: "Measure nanoTDF performance",
	RunE:  nanoTdfPerf,
	Args:  cobra.MinimumNArgs(2),
}

func init() {
	ExamplesCmd.AddCommand(nanoPerfCmd)
}

func nanoTdfPerf(cmd *cobra.Command, args []string) error {
	if len(args) < 2 {
		return cmd.Usage()
	}

	plainText := args[0]
	numTDFs, err := strconv.Atoi(args[1])
	if err != nil || numTDFs <= 0 {
		return fmt.Errorf("invalid number of TDFs: %s", args[1])
	}

	// Create new offline client
	client, err := sdk.New(cmd.Context().Value(RootConfigKey).(*ExampleConfig).PlatformEndpoint,
		sdk.WithInsecurePlaintextConn(),
		sdk.WithClientCredentials("opentdf-sdk", "secret", nil),
		sdk.WithTokenEndpoint("http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/token"),
	)
	if err != nil {
		return err
	}

	//
	// NanoTDF
	//

	attributes := []string{
		"https://example.com/attr/attr1/value/value1",
	}

	nanoTDFConfig, err := client.NewNanoTDFConfig()
	if err != nil {
		return err
	}

	nanoTDFConfig.SetAttributes(attributes)
	nanoTDFConfig.SetKasURL(fmt.Sprintf("http://%s/kas", cmd.Flag("platformEndpoint").Value.String()))
	nanoTDFConfig.EnableECDSAPolicyBinding()

	var wg sync.WaitGroup
	results := make(chan result, numTDFs)

	startTime := time.Now()

	for i := 0; i < numTDFs; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			strReader := strings.NewReader(plainText)
			var buffer bytes.Buffer

			start := time.Now()
			_, err := client.CreateNanoTDF(&buffer, strReader, *nanoTDFConfig)
			duration := time.Since(start)

			nanoTDFData := buffer.Bytes()
			results <- result{index: i, data: nanoTDFData, err: err, duration: duration}
		}(i)
	}

	wg.Wait()
	close(results)

	var totalDuration time.Duration
	var successCount int

	for res := range results {
		if res.err != nil {
			cmd.Printf("CreateNanoTDF %d Failed: %v\n", res.index, res.err)
			continue
		}
		totalDuration += res.duration
		successCount++
		cmd.Printf("NanoTDF %d size: %d bytes, creation time: %d ms\n", res.index, len(res.data), res.duration.Milliseconds())
	}

	if successCount == 0 {
		return fmt.Errorf("all NanoTDF creations failed")
	}

	totalTime := time.Since(startTime)
	//averageDuration := totalDuration / int64(successCount)

	cmd.Printf("totalDuration: %d \n", totalDuration)
	cmd.Printf("successCount: %d \n", successCount)

	//cmd.Printf("Average creation time: %d ms\n", averageDuration)
	cmd.Printf("Total creation time: %d ms\n", totalTime.Milliseconds())

	return nil
}

type result struct {
	index    int
	data     []byte
	err      error
	duration time.Duration
}

//func dumpNanoTDF(cmd *cobra.Command, nTdfFile string) error {
//	f, err := os.Open(nTdfFile)
//	if err != nil {
//		return err
//	}
//
//	buf := bytes.Buffer{}
//	_, err = buf.ReadFrom(f)
//	if err != nil {
//		return err
//	}
//
//	cmd.Println(string(ocrypto.Base64Encode(buf.Bytes())))
//
//	return nil
//}
