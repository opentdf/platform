package sdk_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestREADMECodeBlocks verifies that all Go code blocks in the README compile successfully.
// This ensures the documentation stays accurate and up-to-date with the actual API.
func TestREADMECodeBlocks(t *testing.T) {
	// Read the README file
	readmePath := filepath.Join("..", "sdk", "README.md")
	content, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("Failed to read README.md: %v", err)
	}

	// Extract Go code blocks
	codeBlocks := extractGoCodeBlocks(string(content))
	if len(codeBlocks) == 0 {
		t.Fatal("No Go code blocks found in README.md")
	}

	t.Logf("Found %d Go code block(s) in README.md", len(codeBlocks))

	// Test each code block that is a complete program
	testedCount := 0
	for i, code := range codeBlocks {
		// Only test complete programs (those with package main)
		if !strings.Contains(code, "package main") {
			t.Logf("Skipping code block %d (not a complete program)", i+1)
			continue
		}

		testedCount++
		t.Run(formatBlockName(i, code), func(t *testing.T) {
			if err := testCodeBlock(t, code); err != nil {
				t.Errorf("Code block %d failed to compile:\n%v", i+1, err)
			}
		})
	}

	if testedCount == 0 {
		t.Fatal("No complete program code blocks found in README.md")
	}
	t.Logf("Tested %d complete program(s)", testedCount)
}

// extractGoCodeBlocks finds all Go code blocks in the markdown content.
func extractGoCodeBlocks(content string) []string {
	// Match code blocks that start with ```go and end with ```
	re := regexp.MustCompile("(?s)```go\n(.*?)```")
	matches := re.FindAllStringSubmatch(content, -1)

	blocks := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			blocks = append(blocks, match[1])
		}
	}
	return blocks
}

// formatBlockName creates a readable test name from the code block.
func formatBlockName(index int, code string) string {
	lines := strings.Split(strings.TrimSpace(code), "\n")
	if len(lines) == 0 {
		return "empty_block"
	}

	// Try to find a meaningful identifier in the first few lines
	for _, line := range lines[:min(5, len(lines))] {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package ") {
			return strings.TrimPrefix(line, "package ")
		}
		if strings.HasPrefix(line, "func ") {
			return strings.Fields(line)[1]
		}
	}

	return "code_block_" + string(rune('A'+index))
}

// testCodeBlock attempts to compile a code block.
func testCodeBlock(t *testing.T, code string) error {
	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "readme-test-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	// Write the code to main.go
	mainPath := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(mainPath, []byte(code), 0644); err != nil {
		return err
	}

	// Initialize go module
	cmd := exec.Command("go", "mod", "init", "example")
	cmd.Dir = tmpDir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Logf("go mod init output: %s", output)
		return err
	}

	// Get the absolute path to the platform directory
	// When running from sdk directory, we need to go up one level
	platformDir, err := filepath.Abs(filepath.Join(".."))
	if err != nil {
		return err
	}

	// Add replace directives for local modules
	replacements := []string{
		"github.com/opentdf/platform/sdk=" + filepath.Join(platformDir, "sdk"),
		"github.com/opentdf/platform/lib/ocrypto=" + filepath.Join(platformDir, "lib/ocrypto"),
		"github.com/opentdf/platform/protocol/go=" + filepath.Join(platformDir, "protocol/go"),
	}

	for _, replace := range replacements {
		cmd := exec.Command("go", "mod", "edit", "-replace", replace)
		cmd.Dir = tmpDir
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Logf("go mod edit output: %s", output)
			return err
		}
	}

	// Run go mod tidy
	cmd = exec.Command("go", "mod", "tidy")
	cmd.Dir = tmpDir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Logf("go mod tidy output: %s", output)
		return err
	}

	// Attempt to build
	cmd = exec.Command("go", "build", "-o", "/dev/null", "main.go")
	cmd.Dir = tmpDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Build output:\n%s", output)
		return err
	}

	t.Logf("Code block compiled successfully")
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
