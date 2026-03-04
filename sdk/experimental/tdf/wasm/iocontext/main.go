// Canary: io, context, strings, strconv, fmt, errors
// These are used pervasively in TDF logic for stream processing,
// error handling, and string manipulation. Most are importable
// in TinyGo but have test failures — this validates the specific
// operations the TDF code actually uses.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func main() {
	// io.Reader / io.Writer (used for TDF segment streaming)
	var buf bytes.Buffer
	data := []byte("segment payload data for testing")
	n, err := buf.Write(data)
	if err != nil || n != len(data) {
		panic("io.Writer failed")
	}

	out := make([]byte, len(data))
	n, err = buf.Read(out)
	if err != nil || n != len(data) {
		panic("io.Reader failed")
	}

	// io.ReadFull (used when reading exact segment sizes)
	buf.Reset()
	buf.Write(data)
	exact := make([]byte, 10)
	n, err = io.ReadFull(&buf, exact)
	if err != nil || n != 10 {
		panic("io.ReadFull failed")
	}

	// io.MultiReader (used in zipstream for composing nonce + cipher)
	r1 := bytes.NewReader([]byte("nonce"))
	r2 := bytes.NewReader([]byte("ciphertext"))
	multi := io.MultiReader(r1, r2)
	combined, err := io.ReadAll(multi)
	if err != nil {
		panic("io.MultiReader failed")
	}
	if string(combined) != "nonceciphertext" {
		panic("io.MultiReader output mismatch")
	}

	// context.Background (used in all TDF operations)
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if ctx.Err() == nil {
		panic("context cancellation not working")
	}

	// strings operations (used in manifest parsing, URL handling)
	s := "AES-256-GCM"
	if !strings.Contains(s, "GCM") {
		panic("strings.Contains failed")
	}
	if strings.ToLower(s) != "aes-256-gcm" {
		panic("strings.ToLower failed")
	}
	parts := strings.Split("split-0:kas1", ":")
	if len(parts) != 2 {
		panic("strings.Split failed")
	}

	// strconv (used for segment index conversion)
	idx := strconv.Itoa(42)
	if idx != "42" {
		panic("strconv.Itoa failed")
	}
	parsed, err := strconv.Atoi("42")
	if err != nil || parsed != 42 {
		panic("strconv.Atoi failed")
	}

	// fmt.Sprintf (used for error messages)
	msg := fmt.Sprintf("segment %d: size %d", 0, 1024)
	if msg != "segment 0: size 1024" {
		panic("fmt.Sprintf failed")
	}

	// fmt.Errorf with %w (used for error wrapping in TDF code)
	inner := errors.New("inner error")
	wrapped := fmt.Errorf("tdf encrypt failed: %w", inner)
	if wrapped == nil {
		panic("fmt.Errorf returned nil")
	}

	// errors.Is (used for error checking in TDF code)
	if !errors.Is(wrapped, inner) {
		panic("errors.Is failed to unwrap")
	}
}
