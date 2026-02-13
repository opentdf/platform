package host

// Test WASI setup for Go wasip1 modules with //go:wasmexport.
//
// Go 1.25's wasip1 runtime calls proc_exit(0) after main() returns, which
// causes wazero's default WASI to close the module — making exported functions
// uncallable. This uses wazero's FunctionExporter to get real WASI functions
// while overriding proc_exit with a panic (non-sys.ExitError) so the module
// stays alive for subsequent wasmexport calls.

import (
	"context"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// procExitSignal is a non-sys.ExitError panic value. Because it does NOT
// implement wazero's sys.ExitError interface, the panic halts _start execution
// without closing the module.
type procExitSignal struct{ code uint32 }

func (p procExitSignal) Error() string {
	return fmt.Sprintf("proc_exit(%d)", p.code)
}

// registerTestWASI registers a full "wasi_snapshot_preview1" host module
// with all real WASI functions, but overrides proc_exit so it panics
// instead of closing the module.
func registerTestWASI(ctx context.Context, rt wazero.Runtime) error {
	builder := rt.NewHostModuleBuilder("wasi_snapshot_preview1")
	wasi_snapshot_preview1.NewFunctionExporter().ExportFunctions(builder)

	// Override proc_exit: panic with non-ExitError so module stays alive.
	builder.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, code uint32) {
			panic(procExitSignal{code})
		}).Export("proc_exit")

	_, err := builder.Instantiate(ctx)
	return err
}
