package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"golang.org/x/vuln/scan"
	"gopkg.in/yaml.v3"
)

// Message is a govulncheck JSON message. Using a map preserves all fields
// (including any added in future govulncheck versions) during re-serialization.
type Message = map[string]json.RawMessage

type OSVEntry struct {
	ID string `json:"id"`
}

type Finding struct {
	OSV   string  `json:"osv"`
	Trace []Frame `json:"trace"`
}

type Frame struct {
	Module   string `json:"module"`
	Function string `json:"function"`
}

// Allowlist entry from .govulncheck-ignore.yaml.

type AllowlistEntry struct {
	ID      string    `yaml:"id"`
	Reason  string    `yaml:"reason"`
	Expires string    `yaml:"expires"` // YYYY-MM-DD
	expires time.Time // parsed from Expires during loading
}

const exitCodeInputError = 2

func main() {
	outputFile := flag.String("output", "", "path to govulncheck JSON output file (required)")
	allowlistFile := flag.String("allowlist", ".govulncheck-ignore.yaml", "path to allowlist YAML file")
	flag.Parse()

	if *outputFile == "" {
		fmt.Fprintln(os.Stderr, "error: -output flag is required")
		flag.Usage()
		os.Exit(exitCodeInputError)
	}

	allowlist, err := loadAllowlist(*allowlistFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading allowlist: %v\n", err)
		os.Exit(exitCodeInputError)
	}

	calledIDs, err := findCalledVulns(*outputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing govulncheck output: %v\n", err)
		os.Exit(exitCodeInputError)
	}

	excluded, failed := checkFindings(calledIDs, allowlist, time.Now().UTC())
	exitCode := printReport(os.Stdout, *outputFile, excluded, failed)
	os.Exit(exitCode)
}

func loadAllowlist(path string) (map[string]AllowlistEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
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
		parsed, err := time.Parse(time.DateOnly, e.Expires)
		if err != nil {
			return nil, fmt.Errorf("allowlist entry %s: invalid expires date %q (expected YYYY-MM-DD)", e.ID, e.Expires)
		}
		e.expires = parsed
		if existing, ok := m[e.ID]; ok && existing.expires.Before(e.expires) {
			continue // keep the entry with the sooner expiry
		}
		m[e.ID] = e
	}
	return m, nil
}

// findCalledVulns parses govulncheck JSON and returns sorted OSV IDs with called findings.
func findCalledVulns(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	calledSet := make(map[string]bool)

	dec := json.NewDecoder(f)
	for dec.More() {
		var msg Message
		if err := dec.Decode(&msg); err != nil {
			return nil, fmt.Errorf("decoding JSON object: %w", err)
		}

		raw, ok := msg["finding"]
		if !ok {
			continue
		}
		var finding Finding
		if err := json.Unmarshal(raw, &finding); err != nil {
			return nil, fmt.Errorf("decoding finding: %w", err)
		}
		if isCalled(&finding) {
			calledSet[finding.OSV] = true
		}
	}

	ids := make([]string, 0, len(calledSet))
	for id := range calledSet {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

// isCalled returns true if the finding has a trace with function-level frames.
func isCalled(f *Finding) bool {
	if len(f.Trace) == 0 {
		return false
	}
	return f.Trace[0].Function != ""
}

func checkFindings(calledIDs []string, allowlist map[string]AllowlistEntry, now time.Time) ([]string, []string) {
	var excluded, failed []string
	nowDate := now.UTC().Truncate(24 * time.Hour) //nolint:mnd // truncate to date

	for _, id := range calledIDs {
		entry, inAllowlist := allowlist[id]
		if !inAllowlist {
			failed = append(failed, id)
			continue
		}

		if nowDate.After(entry.expires) {
			failed = append(failed, id)
			continue
		}

		excluded = append(excluded, id)
	}
	return excluded, failed
}

func printReport(w io.Writer, jsonPath string, excluded, failed []string) int {
	if len(excluded) > 0 {
		fmt.Fprintln(w, "EXCLUDED (allowlisted, not expired):")
		for _, id := range excluded {
			fmt.Fprintf(w, "  %s\n", id)
		}
		fmt.Fprintln(w)
	}

	if len(failed) > 0 {
		fmt.Fprintf(w, "FAILED (%d unresolved vulnerabilities):\n\n", len(failed))

		// Write filtered JSON containing only non-excluded findings,
		// then pipe through govulncheck -mode convert for native text output.
		if err := printFilteredText(w, jsonPath, failed); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not render text output: %v\n", err)
			// Fallback: just list the IDs.
			for _, id := range failed {
				fmt.Fprintf(w, "  %s: https://pkg.go.dev/vuln/%s\n", id, id)
			}
		}

		fmt.Fprintln(w)
		fmt.Fprintf(w, "Result: FAIL (%d unresolved vulnerabilities)\n", len(failed))
		return 1
	}

	if len(excluded) == 0 {
		fmt.Fprintln(w, "No vulnerabilities detected.")
	}
	fmt.Fprintln(w, "Result: PASS")
	return 0
}

// printFilteredText builds a filtered JSON stream (only findings for failedIDs)
// and converts it to native govulncheck text output via the scan library.
func printFilteredText(w io.Writer, jsonPath string, failedIDs []string) error {
	failedSet := make(map[string]bool, len(failedIDs))
	for _, id := range failedIDs {
		failedSet[id] = true
	}

	f, err := os.Open(jsonPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Build filtered JSON in memory.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	dec := json.NewDecoder(f)
	for dec.More() {
		var msg Message
		if err := dec.Decode(&msg); err != nil {
			return fmt.Errorf("decoding JSON object: %w", err)
		}

		// Pass through all message types except OSV/finding for excluded vulns.
		if raw, ok := msg["osv"]; ok {
			var osv OSVEntry
			if err := json.Unmarshal(raw, &osv); err == nil && !failedSet[osv.ID] {
				continue
			}
		}
		if raw, ok := msg["finding"]; ok {
			var finding Finding
			if err := json.Unmarshal(raw, &finding); err == nil && !failedSet[finding.OSV] {
				continue
			}
		}

		if err := enc.Encode(msg); err != nil {
			return fmt.Errorf("encoding filtered message: %w", err)
		}
	}

	// Convert filtered JSON to text using govulncheck's scan library.
	cmd := scan.Command(context.Background(), "-mode", "convert")
	cmd.Stdin = &buf
	cmd.Stdout = w
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting govulncheck convert: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		// govulncheck exits with a typed error (ExitCode) when vulns are present,
		// which is expected. Propagate only unexpected errors.
		if _, ok := err.(interface{ ExitCode() int }); !ok {
			return fmt.Errorf("govulncheck convert failed: %w", err)
		}
	}
	return nil
}
