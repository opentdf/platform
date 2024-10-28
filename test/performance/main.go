package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/sdk"
)

//go:embed no-attrs.txt.tdf
var embeddedTDFNoAttributes []byte

func makeHTTPRequest(url string, wg *sync.WaitGroup, results chan<- time.Duration, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}        // Acquire a token
	defer func() { <-sem }() // Release the token

	start := time.Now()
	_, err := http.Get(url)
	duration := time.Since(start)

	if err != nil {
		results <- 0
		return
	}
	results <- duration
}

func makeSDKListAttributesRequest(ctx context.Context, wg *sync.WaitGroup, client *sdk.SDK, results chan<- time.Duration, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}        // Acquire a token
	defer func() { <-sem }() // Release the token

	start := time.Now()

	rsp, err := client.Attributes.ListAttributes(ctx, &attributes.ListAttributesRequest{})
	if rsp == nil {
		panic("failed to list attributes")
	}
	duration := time.Since(start)

	if err != nil {
		results <- 0
		return
	}
	results <- duration
}

func makeSDKDecryptRequest(wg *sync.WaitGroup, client *sdk.SDK, results chan<- time.Duration, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}        // Acquire a token
	defer func() { <-sem }() // Release the token

	start := time.Now()

	rsp, err := client.LoadTDF(bytes.NewReader(embeddedTDFNoAttributes))
	if rsp == nil {
		panic("failed to load TDF bytes")
	}
	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, rsp)
	// fmt.Println(string(buf.Bytes())) // decrypted content = "some text"
	duration := time.Since(start)

	if err != nil {
		results <- 0
		return
	}
	results <- duration
}

func calculateRPS(requests int, totalDuration time.Duration) float64 {
	return float64(requests) / totalDuration.Seconds()
}

func runTestHTTP(url string, concurrentRequests, maxRequests int) float64 {
	sem := make(chan struct{}, concurrentRequests)

	var wg sync.WaitGroup
	results := make(chan time.Duration, maxRequests) // Limit channel to maxRequests
	startTime := time.Now()

	for i := 0; i < maxRequests; i++ {
		if i >= concurrentRequests {
			break
		}
		wg.Add(1)
		go makeHTTPRequest(url, &wg, results, sem)
	}

	wg.Wait()
	close(results)

	totalDuration := time.Since(startTime)
	successfulRequests := 0
	for r := range results {
		if r > 0 {
			successfulRequests++
		}
	}

	rps := calculateRPS(successfulRequests, totalDuration)
	fmt.Printf("Concurrency: %d, Requests per second: %.2f\n", concurrentRequests, rps)

	return rps
}

func runTestGRPC(concurrentRequests, maxRequests, testNumber int) float64 {
	sem := make(chan struct{}, concurrentRequests)

	var wg sync.WaitGroup
	results := make(chan time.Duration, maxRequests) // Limit channel to maxRequests
	startTime := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, _ := sdk.New("http://localhost:8080",
		sdk.WithInsecurePlaintextConn(),
		sdk.WithClientCredentials("opentdf", "secret", nil),
	)

	for i := 0; i < maxRequests; i++ {
		if i >= concurrentRequests {
			break
		}
		wg.Add(1)
		switch testNumber {
		case 1:
			go makeSDKListAttributesRequest(ctx, &wg, client, results, sem)
		case 2:
			go makeSDKDecryptRequest(&wg, client, results, sem)
		}
	}

	wg.Wait()
	close(results)

	totalDuration := time.Since(startTime)
	successfulRequests := 0
	for r := range results {
		if r > 0 {
			successfulRequests++
		}
	}

	rps := calculateRPS(successfulRequests, totalDuration)
	fmt.Printf("Concurrency: %d, Requests per second: %.2f\n", concurrentRequests, rps)

	return rps
}

type Result struct {
	Resource   string  `json:"resource"`
	AverageRps float64 `json:"averageRPS"`
}

var results = make([]Result, 0)

func main() {
	httpEndpoints := []string{
		"http://localhost:8080/.well-known/opentdf-configuration",
		"http://localhost:8080/kas/kas_public_key",
		"http://localhost:8080/kas/v2/kas_public_key",
	}

	initialConcurrency := 10
	maxConcurrency := 1500 // Set an upper limit for concurrency
	maxRequests := 2000    // Maximum total requests to send
	totalRuns := 10        // Number of times to run the test per endpoint

	file, err := os.OpenFile("results.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	concurrentRequests := initialConcurrency
	fmt.Println("\nStarting tests for gRPC")
	var totalRPS float64

	for testCount := 1; testCount < 3; testCount++ {
		concurrentRequests = initialConcurrency
		var test string
		switch testCount {
		case 1:
			test = "sdk.ListAttributes"
		case 2:
			test = "sdk.LoadTDF (no attributes TDF with Rewrap call)"
		}
		for run := 1; run <= totalRuns; run++ {
			fmt.Printf("\nStarting test %s run %d\n", test, run)
			rps := runTestGRPC(concurrentRequests, maxRequests, testCount)
			totalRPS += rps

			// Double concurrency, but cap it at maxConcurrency
			if concurrentRequests*2 <= maxConcurrency {
				concurrentRequests *= 2
			} else {
				concurrentRequests = maxConcurrency
			}

			time.Sleep(2 * time.Second) // Pause between test runs
		}
		averageRPS := totalRPS / float64(totalRuns)
		fmt.Printf("\nAverage Requests per second for gRPC %s after %d runs: %.2f\n", test, totalRuns, averageRPS)

		r := Result{
			Resource:   test,
			AverageRps: averageRPS,
		}
		results = append(results, r)
	}

	for _, url := range httpEndpoints {
		concurrentRequests = initialConcurrency
		fmt.Printf("\nStarting tests for endpoint: %s\n", url)
		totalRPS = 0

		for run := 1; run <= totalRuns; run++ {
			fmt.Printf("\nStarting test run %d for %s...\n", run, url)
			rps := runTestHTTP(url, concurrentRequests, maxRequests)
			totalRPS += rps

			// Double concurrency, but cap it at maxConcurrency
			if concurrentRequests*2 <= maxConcurrency {
				concurrentRequests *= 2
			} else {
				concurrentRequests = maxConcurrency
			}

			time.Sleep(2 * time.Second) // Pause between test runs
		}

		averageRPS := totalRPS / float64(totalRuns)
		fmt.Printf("\nAverage Requests per second for %s after %d runs: %.2f\n", url, totalRuns, averageRPS)

		r := Result{
			Resource:   url,
			AverageRps: averageRPS,
		}
		results = append(results, r)

	}
	resultsJSON, err := json.Marshal(results)

	if _, err := file.Write(resultsJSON); err != nil {
		fmt.Println("Error writing to file:", err)
	}
}
