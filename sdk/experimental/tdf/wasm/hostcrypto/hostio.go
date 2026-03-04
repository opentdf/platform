//go:build wasip1

package hostcrypto

import "io"

// ── Raw host imports (private) ──────────────────────────────────────

// _read_input pulls data from the host-provided readable source.
// Returns bytes read on success, 0 for EOF, 0xFFFFFFFF on error.
//
//go:wasmimport io read_input
func _read_input(buf_ptr, buf_capacity uint32) uint32

// _write_output pushes data to the host-provided writable sink.
// Returns bytes written on success, 0xFFFFFFFF on error.
//
//go:wasmimport io write_output
func _write_output(buf_ptr, buf_len uint32) uint32

// ── Exported wrappers ───────────────────────────────────────────────

// ReadInput reads up to len(buf) bytes from the host input source.
// Returns the number of bytes read and io.EOF when the source is exhausted.
func ReadInput(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	result := _read_input(slicePtr(buf), uint32(len(buf)))
	if result == errSentinel {
		return 0, getLastError()
	}
	if result == 0 {
		return 0, io.EOF
	}
	return int(result), nil
}

// WriteOutput writes buf to the host output sink.
// Returns the number of bytes written.
func WriteOutput(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	result := _write_output(slicePtr(buf), uint32(len(buf)))
	if result == errSentinel {
		return 0, getLastError()
	}
	return int(result), nil
}
