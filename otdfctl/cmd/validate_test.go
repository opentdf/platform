package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opentdf/platform/otdfctl/cmd/tdf"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// asOtdfctlEnv, when set, makes the test binary run as otdfctl with the
// JSON-encoded argument list it holds. `validate` reports its result through
// os.Exit, so its exit codes can only be observed from another process.
const asOtdfctlEnv = "OTDFCTL_TEST_RUN_AS_OTDFCTL"

// TestMain intercepts before m.Run because the testing package turns os.Exit(0)
// inside a test into a failure, and exit 0 is half of the contract under test.
func TestMain(m *testing.M) {
	if raw, ok := os.LookupEnv(asOtdfctlEnv); ok {
		var args []string
		if err := json.Unmarshal([]byte(raw), &args); err != nil {
			panic(err)
		}
		os.Args = append([]string{"otdfctl"}, args...)
		cobra.EnableTraverseRunHooks = true
		Execute()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type otdfctlRun struct {
	code   int
	stdout string
	stderr string
}

// runOtdfctl runs otdfctl in a child process with an empty HOME, so no profile,
// keyring entry, or config file is available to it.
func runOtdfctl(t *testing.T, args ...string) otdfctlRun {
	t.Helper()

	raw, err := json.Marshal(args)
	require.NoError(t, err)

	home := t.TempDir()
	cmd := exec.CommandContext(t.Context(), os.Args[0])
	cmd.Env = append(os.Environ(),
		asOtdfctlEnv+"="+string(raw),
		"HOME="+home,
		"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		require.ErrorAs(t, err, &exitErr, "otdfctl did not run")
		code = exitErr.ExitCode()
	}
	return otdfctlRun{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func TestValidateCommandContract(t *testing.T) {
	validTDF, err := filepath.Abs(filepath.Join("tdf", "testdata", "valid.tdf"))
	require.NoError(t, err)

	garbage := filepath.Join(t.TempDir(), "garbage.tdf")
	require.NoError(t, os.WriteFile(garbage, []byte(strings.Repeat("not a TDF\n", 16)), 0o600))

	t.Run("valid TDF", func(t *testing.T) {
		r := runOtdfctl(t, "validate", validTDF)
		assert.Equal(t, 0, r.code, "stderr: %s", r.stderr)
		assert.Equal(t, `{"valid":true}`+"\n", r.stdout)
	})

	// The xtest Go shim passes connection flags to every otdfctl command. They
	// must not make validate authenticate: nothing listens on this host.
	t.Run("valid TDF with connection flags", func(t *testing.T) {
		r := runOtdfctl(t,
			"--host", "http://127.0.0.1:1",
			"--tls-no-verify",
			"--log-level", "debug",
			"--with-client-creds", `{"clientId":"id","clientSecret":"secret"}`,
			"validate", validTDF,
		)
		assert.Equal(t, 0, r.code, "stderr: %s", r.stderr)
		assert.Equal(t, `{"valid":true}`+"\n", r.stdout)
	})

	t.Run("not a TDF", func(t *testing.T) {
		r := runOtdfctl(t, "validate", garbage)
		assert.Equal(t, tdf.ExitCodeInvalidTDF, r.code, "stderr: %s", r.stderr)

		line, rest, _ := strings.Cut(r.stdout, "\n")
		assert.Empty(t, rest, "stdout must be exactly one line")
		var got struct {
			Valid  *bool  `json:"valid"`
			Reason string `json:"reason"`
		}
		require.NoError(t, json.Unmarshal([]byte(line), &got), "stdout: %q", r.stdout)
		require.NotNil(t, got.Valid, "stdout must say valid:false explicitly")
		assert.False(t, *got.Valid)
		assert.NotEmpty(t, got.Reason)
	})

	// Every failure to check must exit with something other than 0 or 3, and
	// print nothing a caller could mistake for a verdict.
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "missing file", args: []string{"validate", filepath.Join(t.TempDir(), "missing.tdf")}},
		{name: "directory", args: []string{"validate", t.TempDir()}},
		{name: "no file", args: []string{"validate"}},
		{name: "two files", args: []string{"validate", validTDF, garbage}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runOtdfctl(t, tc.args...)
			assert.NotContains(t, []int{0, tdf.ExitCodeInvalidTDF}, r.code, "stderr: %s", r.stderr)
			assert.Empty(t, r.stdout)
			assert.NotEmpty(t, r.stderr)
		})
	}
}
