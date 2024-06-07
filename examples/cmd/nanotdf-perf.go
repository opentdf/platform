package cmd

import (
	"bytes"
	"fmt"
	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	nTdfPerf = &cobra.Command{
		Use:   "nanotdf-perf [numNanoTDFs] [requestsPerSecond]",
		Short: "Measure nanoTDF performance",
		RunE:  nanoPerf,
		Args:  cobra.MinimumNArgs(2),
	}
	rps          int
	requestCount int
	startTime    time.Time
	sendEndTime  time.Time
	mu           sync.Mutex
)

func init() {
	ExamplesCmd.AddCommand(nTdfPerf)
}

func nanoPerf(cmd *cobra.Command, args []string) error {
	if len(args) < 2 {
		return cmd.Usage()
	}

	rps, err := strconv.Atoi(args[1])
	if err != nil {
		return err
	}
	numNanoTDFs, err := strconv.Atoi(args[0])
	if err != nil {
		return err
	}
	fmt.Println("-----------------------------------------------")
	fmt.Printf("Creating %d NanoTDFs\n", numNanoTDFs)
	fmt.Println("-----------------------------------------------")
	platformEndpoint := cmd.Context().Value(RootConfigKey).(*ExampleConfig).PlatformEndpoint
	client, config, err := initializeClient(platformEndpoint)
	fmt.Println(platformEndpoint)
	if err != nil {
		return err
	}

	nanoTDFArray := make([][]byte, numNanoTDFs)

	for i := 0; i < numNanoTDFs; i++ {
		nanoTDFArray[i], err = createNanoTDF(client, config, plainText)
		if err != nil {
			return err
		}
	}
	fmt.Println("-----------------------------------------------")
	fmt.Printf("Reading %d NanoTDFs at %d Requests per second \n", numNanoTDFs, rps)
	fmt.Println("-----------------------------------------------")

	var readWaitGroup sync.WaitGroup

	startTime := time.Now()
	ticker := time.NewTicker(time.Second / time.Duration(rps))
	defer ticker.Stop()

	var endTime time.Time

	for i := 0; i < numNanoTDFs; i++ {
		<-ticker.C

		readWaitGroup.Add(1)

		go func(id int) {
			defer readWaitGroup.Done()
			if id == numNanoTDFs-1 {
				endTime = time.Now()
				totalTime := endTime.Sub(startTime)
				actualRps := float64(numNanoTDFs) / totalTime.Seconds()

				fmt.Println("-----------------------------------------------")
				fmt.Printf("Actual RPS: %f\n", actualRps)
				fmt.Println("-----------------------------------------------")
			}
			err = readNanoTDF(client, nanoTDFArray[id])
			if err != nil {
				fmt.Println("READ - FAILED")
			}
		}(i)
	}

	readWaitGroup.Wait()
	return nil
}

func initializeClient(platformEndpoint string) (*sdk.SDK, *sdk.NanoTDFConfig, error) {
	client, err := sdk.New(platformEndpoint,
		sdk.WithInsecurePlaintextConn(),
		sdk.WithClientCredentials("opentdf-sdk", "secret", nil),
		sdk.WithTokenEndpoint("http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/token"),
	)
	if err != nil {
		return nil, nil, err
	}

	nanoTDFConfig, err := client.NewNanoTDFConfig()
	if err != nil {
		return nil, nil, err
	}

	err = nanoTDFConfig.SetKasURL(fmt.Sprintf("http://%s/kas", platformEndpoint))
	if err != nil {
		return nil, nil, err
	}

	nanoTDFConfig.EnableECDSAPolicyBinding()

	return client, nanoTDFConfig, nil
}

func createNanoTDF(client *sdk.SDK, config *sdk.NanoTDFConfig, plainText string) ([]byte, error) {
	var nTdfBuffer bytes.Buffer
	strReader := strings.NewReader(plainText)

	_, err := client.CreateNanoTDF(&nTdfBuffer, strReader, *config)
	if err != nil {
		fmt.Printf("CREATE - FAILED\n")
		return nil, err
	}

	return nTdfBuffer.Bytes(), nil
}

func readNanoTDF(client *sdk.SDK, nanoTDF []byte) error {
	var outBuf bytes.Buffer
	nTdfBuffer := bytes.NewReader(nanoTDF)

	_, err := client.ReadNanoTDF(io.Writer(&outBuf), nTdfBuffer)
	if err != nil {
		fmt.Println("READ - FAILED")
		return err
	}

	return nil
}
