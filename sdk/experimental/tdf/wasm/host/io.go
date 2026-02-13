package host

import (
	"context"
	"io"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// RegisterIO instantiates the "io" host module on the given wazero.Runtime.
// The IOConfig provides the input/output sources for WASM I/O callbacks.
func RegisterIO(ctx context.Context, rt wazero.Runtime, cfg IOConfig) (api.Closer, error) {
	return rt.NewHostModuleBuilder("io").
		NewFunctionBuilder().WithFunc(newReadInput(cfg)).Export("read_input").
		NewFunctionBuilder().WithFunc(newWriteOutput(cfg)).Export("write_output").
		Instantiate(ctx)
}

// newReadInput returns a host function that reads from cfg.Input into WASM memory.
// Returns bytes read, 0 for EOF, errSentinel on error.
func newReadInput(cfg IOConfig) func(context.Context, api.Module, uint32, uint32) uint32 {
	return func(_ context.Context, mod api.Module, bufPtr, bufCapacity uint32) uint32 {
		if cfg.Input == nil {
			return 0 // EOF
		}
		buf := make([]byte, bufCapacity)
		n, err := cfg.Input.Read(buf)
		if n > 0 {
			if !writeBytes(mod, bufPtr, buf[:n]) {
				setLastError(errOOB)
				return errSentinel
			}
			return uint32(n)
		}
		if err == io.EOF || err == nil {
			return 0 // EOF
		}
		setLastError(err)
		return errSentinel
	}
}

// newWriteOutput returns a host function that writes from WASM memory to cfg.Output.
// Returns bytes written or errSentinel on error.
func newWriteOutput(cfg IOConfig) func(context.Context, api.Module, uint32, uint32) uint32 {
	return func(_ context.Context, mod api.Module, bufPtr, bufLen uint32) uint32 {
		if cfg.Output == nil {
			setLastError(hostErr("host: no output writer configured"))
			return errSentinel
		}
		data := readBytes(mod, bufPtr, bufLen)
		if data == nil && bufLen > 0 {
			setLastError(errOOB)
			return errSentinel
		}
		n, err := cfg.Output.Write(data)
		if err != nil {
			setLastError(err)
			return errSentinel
		}
		return uint32(n)
	}
}
