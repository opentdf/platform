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
	nanoPerfCmd = &cobra.Command{
		Use:   "nano-perf [numNanoTDFs] [readsPerSecond]",
		Short: "Measure nanoTDF performance",
		RunE:  nanoTdfPerf,
		Args:  cobra.MinimumNArgs(2),
	}
	readsPerSecond int
)

func init() {
	ExamplesCmd.AddCommand(nanoPerfCmd)
}

func nanoTdfPerf(cmd *cobra.Command, args []string) error {
	if len(args) < 2 {
		return cmd.Usage()
	}

	numNanoTDFs, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid number of NanoTDFs: %v", err)
	}

	readsPerSecond, err = strconv.Atoi(args[1])
	if err != nil {
		return fmt.Errorf("invalid number of reads per second: %v", err)
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

	nanoTDFConfig, err := client.NewNanoTDFConfig()
	if err != nil {
		return err
	}

	nanoTDFConfig.SetKasURL(fmt.Sprintf("http://%s/kas", cmd.Flag("platformEndpoint").Value.String()))
	nanoTDFConfig.EnableECDSAPolicyBinding()

	nanoTDFArray := make([][]byte, numNanoTDFs)

	var totalWriteDuration, totalReadDuration time.Duration
	var writeErrors, readErrors int
	var writeStartTime, readStartTime time.Time

	writeDurations := make(chan time.Duration, numNanoTDFs)
	readDurations := make(chan time.Duration, numNanoTDFs)
	writeErrorChan := make(chan bool, numNanoTDFs)
	readErrorChan := make(chan bool, numNanoTDFs)

	writeWg := &sync.WaitGroup{}
	readWg := &sync.WaitGroup{}

	writeWorker := func(id int, jobs <-chan int) {
		defer writeWg.Done()
		for j := range jobs {
			strReader := strings.NewReader(plainText)
			var nTdfBuffer bytes.Buffer

			start := time.Now()
			_, err = client.CreateNanoTDF(&nTdfBuffer, strReader, *nanoTDFConfig)
			duration := time.Since(start)
			if err != nil {
				cmd.Println("CreateNanoTDF Failed")
				writeErrorChan <- true
			} else {
				nanoTDFArray[j] = nTdfBuffer.Bytes()
				writeDurations <- duration
				writeErrorChan <- false
				cmd.Printf("NanoTDF %d created in %s\n", j, duration)
			}
		}
	}

	readWorker := func(id int, jobs <-chan int) {
		defer readWg.Done()
		for j := range jobs {
			var outBuf bytes.Buffer
			nTdfBuffer := bytes.NewReader(nanoTDFArray[j])

			start := time.Now()
			_, err = client.ReadNanoTDF(io.Writer(&outBuf), nTdfBuffer)
			duration := time.Since(start)
			if err != nil {
				cmd.Println("ReadNanoTDF Failed")
				readErrorChan <- true
			} else {
				readDurations <- duration
				readErrorChan <- false
				cmd.Printf("NanoTDF %d read in %s\n", j, duration)
			}
		}
	}

	writeStartTime = time.Now()
	writeJobs := make(chan int, numNanoTDFs)
	for w := 0; w < 5; w++ {
		writeWg.Add(1)
		go writeWorker(w, writeJobs)
	}

	for j := 0; j < numNanoTDFs; j++ {
		writeJobs <- j
	}
	close(writeJobs)
	writeWg.Wait()
	close(writeDurations)
	close(writeErrorChan)
	totalWriteTime := time.Since(writeStartTime)

	readStartTime = time.Now()
	readJobs := make(chan int, numNanoTDFs)
	readInterval := time.Second / time.Duration(readsPerSecond)
	ticker := time.NewTicker(readInterval)

	for w := 0; w < 5; w++ {
		readWg.Add(1)
		go readWorker(w, readJobs)
	}

	go func() {
		for j := 0; j < numNanoTDFs; j++ {
			<-ticker.C
			readJobs <- j
		}
		close(readJobs)
		readWg.Wait()
		close(readDurations)
		close(readErrorChan)
		ticker.Stop()
	}()

	totalReadTime := time.Since(readStartTime)

	for d := range writeDurations {
		totalWriteDuration += d
	}
	for d := range readDurations {
		totalReadDuration += d
	}
	for err := range writeErrorChan {
		if err {
			writeErrors++
		}
	}
	for err := range readErrorChan {
		if err {
			readErrors++
		}
	}

	averageWriteDuration := totalWriteDuration / time.Duration(numNanoTDFs-writeErrors)
	averageReadDuration := totalReadDuration / time.Duration(numNanoTDFs-readErrors)

	writeErrorRate := float64(writeErrors) / float64(numNanoTDFs) * 100
	readErrorRate := float64(readErrors) / float64(numNanoTDFs) * 100

	writeRequestsPerSecond := float64(numNanoTDFs-writeErrors) / totalWriteTime.Seconds()
	readRequestsPerSecond := float64(numNanoTDFs-readErrors) / totalReadTime.Seconds()

	cmd.Printf("Total write duration: %s\n", totalWriteDuration)
	cmd.Printf("Total read duration: %s\n", totalReadDuration)
	cmd.Printf("Average write duration: %s\n", averageWriteDuration)
	cmd.Printf("Average read duration: %s\n", averageReadDuration)
	cmd.Printf("Write error rate: %.2f%%\n", writeErrorRate)
	cmd.Printf("Read error rate: %.2f%%\n", readErrorRate)
	cmd.Printf("Write requests per second: %.2f\n", writeRequestsPerSecond)
	cmd.Printf("Read requests per second: %.2f\n", readRequestsPerSecond)

	cmd.Println("NanoTDFs created and read successfully")

	return nil
}
