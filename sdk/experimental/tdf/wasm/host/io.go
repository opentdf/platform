package host

import (
	"context"
	"io"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// RegisterIO instantiates the "io" host module on the given wazero.Runtime.
// The IOState pointer is captured by closures so the caller can swap
// Input/Output between WASM calls.
func RegisterIO(ctx context.Context, rt wazero.Runtime, state *IOState) (api.Closer, error) {
	return rt.NewHostModuleBuilder("io").
		NewFunctionBuilder().WithFunc(newReadInput(state)).Export("read_input").
		NewFunctionBuilder().WithFunc(newWriteOutput(state)).Export("write_output").
		Instantiate(ctx)
}

// newReadInput returns a host function that reads from state.Input into WASM memory.
// Returns bytes read, 0 for EOF, errSentinel on error.
func newReadInput(state *IOState) func(context.Context, api.Module, uint32, uint32) uint32 {
	return func(_ context.Context, mod api.Module, bufPtr, bufCapacity uint32) uint32 {
		state.mu.Lock()
		r := state.Input
		state.mu.Unlock()
		if r == nil {
			return 0 // EOF
		}
		buf := make([]byte, bufCapacity)
		n, err := r.Read(buf)
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

// newWriteOutput returns a host function that writes from WASM memory to state.Output.
// Returns bytes written or errSentinel on error.
func newWriteOutput(state *IOState) func(context.Context, api.Module, uint32, uint32) uint32 {
	return func(_ context.Context, mod api.Module, bufPtr, bufLen uint32) uint32 {
		state.mu.Lock()
		w := state.Output
		state.mu.Unlock()
		if w == nil {
			setLastError(hostErr("host: no output writer configured"))
			return errSentinel
		}
		data := readBytes(mod, bufPtr, bufLen)
		if data == nil && bufLen > 0 {
			setLastError(errOOB)
			return errSentinel
		}
		n, err := w.Write(data)
		if err != nil {
			setLastError(err)
			return errSentinel
		}
		return uint32(n)
	}
}
