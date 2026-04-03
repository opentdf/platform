package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

// govulncheck JSON message types (stream of pretty-printed JSON objects).

type Message struct {
	OSV     *OSVEntry `json:"osv,omitempty"`
	Finding *Finding  `json:"finding,omitempty"`
}

type OSVEntry struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

type Finding struct {
	OSV   string  `json:"osv"`
	Trace []Frame `json:"trace"`
}

type Frame struct {
	Module   string `json:"module"`
	Package  string `json:"package"`
	Function string `json:"function"`
}

// Allowlist entry from .govulncheck-ignore.yaml.

type AllowlistEntry struct {
	ID      string `yaml:"id"`
	Reason  string `yaml:"reason"`
	Expires string `yaml:"expires"` // YYYY-MM-DD
}

type result struct {
	id      string
	summary string
	status  string // "excluded", "failed", "expired"
	reason  string
	expires string
}

func main() {
	outputFile := flag.String("output", "", "path to govulncheck JSON output file (required)")
	allowlistFile := flag.String("allowlist", ".govulncheck-ignore.yaml", "path to allowlist YAML file")
	flag.Parse()

	if *outputFile == "" {
		fmt.Fprintln(os.Stderr, "error: -output flag is required")
		flag.Usage()
		os.Exit(2) //nolint:mnd // exit code 2 = usage error
	}

	allowlist, err := loadAllowlist(*allowlistFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading allowlist: %v\n", err)
		os.Exit(2) //nolint:mnd // exit code 2 = input error
	}

	osvMap, calledIDs, err := parseGovulncheckJSON(*outputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing govulncheck output: %v\n", err)
		os.Exit(2) //nolint:mnd // exit code 2 = input error
	}

	results := checkFindings(calledIDs, osvMap, allowlist, time.Now())
	exitCode := printReport(results)
	os.Exit(exitCode)
}

func loadAllowlist(path string) (map[string]AllowlistEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// No allowlist file means no exclusions.
			return map[string]AllowlistEntry{}, nil
		}
		return nil, err
	}

	var entries []AllowlistEntry
	if err := yaml.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	m := make(map[string]AllowlistEntry, len(entries))
	for _, e := range entries {
		if e.ID == "" {
			return nil, errors.New("allowlist entry missing 'id' field")
		}
		if e.Reason == "" {
			return nil, fmt.Errorf("allowlist entry %s missing 'reason' field", e.ID)
		}
		if e.Expires == "" {
			return nil, fmt.Errorf("allowlist entry %s missing 'expires' field", e.ID)
		}
		if _, err := time.Parse(time.DateOnly, e.Expires); err != nil {
			return nil, fmt.Errorf("allowlist entry %s: invalid expires date %q (expected YYYY-MM-DD)", e.ID, e.Expires)
		}
		m[e.ID] = e
	}
	return m, nil
}

func parseGovulncheckJSON(path string) (map[string]string, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	osvMap := make(map[string]string)  // id -> summary
	calledSet := make(map[string]bool) // deduped called vuln IDs

	dec := json.NewDecoder(f)
	for dec.More() {
		var msg Message
		if err := dec.Decode(&msg); err != nil {
			return nil, nil, fmt.Errorf("decoding JSON object: %w", err)
		}

		if msg.OSV != nil {
			osvMap[msg.OSV.ID] = msg.OSV.Summary
		}

		if msg.Finding != nil && isCalled(msg.Finding) {
			calledSet[msg.Finding.OSV] = true
		}
	}

	// Sort for deterministic output.
	calledIDs := make([]string, 0, len(calledSet))
	for id := range calledSet {
		calledIDs = append(calledIDs, id)
	}
	sort.Strings(calledIDs)

	return osvMap, calledIDs, nil
}

// isCalled returns true if the finding has a trace with function-level frames,
// indicating the vulnerable code is actually called.
func isCalled(f *Finding) bool {
	if len(f.Trace) == 0 {
		return false
	}
	return f.Trace[0].Function != ""
}

func checkFindings(calledIDs []string, osvMap map[string]string, allowlist map[string]AllowlistEntry, now time.Time) []result {
	var results []result

	for _, id := range calledIDs {
		summary := osvMap[id]
		entry, inAllowlist := allowlist[id]

		if !inAllowlist {
			results = append(results, result{
				id:      id,
				summary: summary,
				status:  "failed",
				reason:  "not in allowlist",
			})
			continue
		}

		expiresDate, _ := time.Parse(time.DateOnly, entry.Expires) // already validated
		if now.After(expiresDate) {
			results = append(results, result{
				id:      id,
				summary: summary,
				status:  "expired",
				reason:  entry.Reason,
				expires: entry.Expires,
			})
			continue
		}

		results = append(results, result{
			id:      id,
			summary: summary,
			status:  "excluded",
			reason:  entry.Reason,
			expires: entry.Expires,
		})
	}

	return results
}

func printReport(results []result) int {
	var excluded, failed []result
	for _, r := range results {
		switch r.status {
		case "excluded":
			excluded = append(excluded, r)
		case "failed", "expired":
			failed = append(failed, r)
		}
	}

	//nolint:forbidigo // CLI tool — stdout is the primary interface
	if len(excluded) > 0 {
		fmt.Println("EXCLUDED (allowlisted, not expired):")
		for _, r := range excluded {
			fmt.Printf("  %s: %s (expires %s)\n", r.id, r.reason, r.expires)
		}
		fmt.Println()
	}

	//nolint:forbidigo // CLI tool — stdout is the primary interface
	if len(failed) > 0 {
		fmt.Println("FAILED (action required):")
		for _, r := range failed {
			switch r.status {
			case "failed":
				fmt.Printf("  %s: %s (not in allowlist)\n", r.id, r.summary)
			case "expired":
				fmt.Printf("  %s: %s (allowlist entry expired on %s)\n", r.id, r.summary, r.expires)
			}
		}
		fmt.Println()
		fmt.Printf("Result: FAIL (%d unresolved vulnerabilities)\n", len(failed))
		return 1
	}

	if len(results) == 0 {
		fmt.Println("No vulnerabilities detected.") //nolint:forbidigo // CLI tool — stdout is the primary interface
	}
	fmt.Println("Result: PASS") //nolint:forbidigo // CLI tool — stdout is the primary interface
	return 0
}
