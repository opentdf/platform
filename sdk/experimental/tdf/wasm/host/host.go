// Package host provides Wazero host modules that fulfill the crypto and I/O
// imports expected by the WASM TDF engine. All crypto is delegated to
// lib/ocrypto; I/O sources are injected by the caller.
//
// See docs/adr/spike-wasm-core-tinygo-hybrid.md for the ABI spec.
package host

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// errSentinel is the uint32 value returned by host functions on error.
const errSentinel = 0xFFFFFFFF

// IOState holds mutable input/output sources for WASM I/O callbacks.
// Closures capture the pointer so the caller can swap Reader/Writer
// between WASM calls (e.g. per-encrypt in tests).
type IOState struct {
	mu     sync.Mutex
	Input  io.Reader
	Output io.Writer
}

// Register registers both the "crypto" and "io" host modules on the given
// wazero.Runtime. The caller is responsible for closing the runtime.
func Register(ctx context.Context, rt wazero.Runtime, io *IOState) error {
	if _, err := RegisterCrypto(ctx, rt); err != nil {
		return fmt.Errorf("register crypto host module: %w", err)
	}
	if _, err := RegisterIO(ctx, rt, io); err != nil {
		return fmt.Errorf("register io host module: %w", err)
	}
	return nil
}

// lastErrorState stores the most recent error message from a host function.
// The WASM guest retrieves it via get_last_error, which clears the value.
type lastErrorState struct {
	mu  sync.Mutex
	msg string
}

var lastErr lastErrorState

func setLastError(err error) {
	lastErr.mu.Lock()
	lastErr.msg = err.Error()
	lastErr.mu.Unlock()
}

func getAndClearLastError() string {
	lastErr.mu.Lock()
	msg := lastErr.msg
	lastErr.msg = ""
	lastErr.mu.Unlock()
	return msg
}

// readBytes reads len bytes from WASM linear memory at ptr.
// Returns nil if the read is out of bounds.
func readBytes(mod api.Module, ptr, length uint32) []byte {
	if length == 0 {
		return nil
	}
	buf, ok := mod.Memory().Read(ptr, length)
	if !ok {
		return nil
	}
	return buf
}

// writeBytes writes data into WASM linear memory at ptr.
// Returns false if the write is out of bounds.
func writeBytes(mod api.Module, ptr uint32, data []byte) bool {
	if len(data) == 0 {
		return true
	}
	return mod.Memory().Write(ptr, data)
}
