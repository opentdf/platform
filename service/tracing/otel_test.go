package tracing

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_InitTracer_CompatibleResourceSchemas_Succeeds(t *testing.T) {
	shutdown, err := InitTracer(context.Background(), Config{
		Enabled: true,
		Provider: ProviderConfig{
			Name: ProviderFile,
			File: &FileConfig{Path: t.TempDir() + "/traces.json"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, shutdown)

	shutdown()
}

func Test_OpenTelemetryDependencies_UseSameVersion(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)

	goMod, err := os.Open(filepath.Join(filepath.Dir(filename), "..", "go.mod"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, goMod.Close()) })

	var otelVersion string
	scanner := bufio.NewScanner(goMod)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || (fields[0] != "go.opentelemetry.io/otel" &&
			!strings.HasPrefix(fields[0], "go.opentelemetry.io/otel/")) {
			continue
		}

		module, version := fields[0], fields[1]
		if module == "go.opentelemetry.io/otel" {
			otelVersion = version
			continue
		}
		require.Equalf(t, otelVersion, version, "%s must match go.opentelemetry.io/otel", module)
	}
	require.NoError(t, scanner.Err())
	require.NotEmpty(t, otelVersion)
}
