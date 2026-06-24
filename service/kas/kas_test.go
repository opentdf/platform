package kas

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/service/kas/access"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilterMechanismsByPreview(t *testing.T) {
	allAlgs := []ocrypto.KeyType{
		"rsa:2048",
		"rsa:4096",
		"ec:secp256r1",
		"ec:secp384r1",
		"hpqt:xwing",
		"hpqt:secp256r1-mlkem768",
	}

	tests := []struct {
		name string
		algs []ocrypto.KeyType
		cfg  *access.KASConfig
		want []ocrypto.KeyType
	}{
		{
			name: "both flags off drops ec and hpqt",
			algs: allAlgs,
			cfg:  &access.KASConfig{},
			want: []ocrypto.KeyType{"rsa:2048", "rsa:4096"},
		},
		{
			name: "top-level ec flag on keeps ec only",
			algs: allAlgs,
			cfg:  &access.KASConfig{ECTDFEnabled: true},
			want: []ocrypto.KeyType{"rsa:2048", "rsa:4096", "ec:secp256r1", "ec:secp384r1"},
		},
		{
			name: "preview ec flag on keeps ec only",
			algs: allAlgs,
			cfg:  &access.KASConfig{Preview: access.Preview{ECTDFEnabled: true}},
			want: []ocrypto.KeyType{"rsa:2048", "rsa:4096", "ec:secp256r1", "ec:secp384r1"},
		},
		{
			name: "top-level hybrid flag on keeps hpqt only",
			algs: allAlgs,
			cfg:  &access.KASConfig{Preview: access.Preview{HybridTDFEnabled: true}},
			want: []ocrypto.KeyType{"rsa:2048", "rsa:4096", "hpqt:xwing", "hpqt:secp256r1-mlkem768"},
		},
		{
			name: "preview hybrid flag on keeps hpqt only",
			algs: allAlgs,
			cfg:  &access.KASConfig{Preview: access.Preview{HybridTDFEnabled: true}},
			want: []ocrypto.KeyType{"rsa:2048", "rsa:4096", "hpqt:xwing", "hpqt:secp256r1-mlkem768"},
		},
		{
			name: "both flags on keeps everything",
			algs: allAlgs,
			cfg:  &access.KASConfig{Preview: access.Preview{ECTDFEnabled: true, HybridTDFEnabled: true, MLKEMTDFEnabled: true}},
			want: allAlgs,
		},
		{
			name: "both preview flags on keeps everything",
			algs: allAlgs,
			cfg: &access.KASConfig{Preview: access.Preview{
				ECTDFEnabled:     true,
				HybridTDFEnabled: true,
				MLKEMTDFEnabled:  true,
			}},
			want: allAlgs,
		},
		{
			name: "empty input returns empty",
			algs: []ocrypto.KeyType{},
			cfg:  &access.KASConfig{Preview: access.Preview{ECTDFEnabled: true, HybridTDFEnabled: true, MLKEMTDFEnabled: true}},
			want: []ocrypto.KeyType{},
		},
		{
			name: "rsa always passes through with no flags",
			algs: []ocrypto.KeyType{"rsa:2048"},
			cfg:  &access.KASConfig{},
			want: []ocrypto.KeyType{"rsa:2048"},
		},
		{
			name: "hybrid on, mlkem off drops pure mlkem but keeps hybrid",
			algs: []ocrypto.KeyType{"rsa:2048", "hpqt:xwing", "mlkem:768", "mlkem:1024"},
			cfg:  &access.KASConfig{Preview: access.Preview{HybridTDFEnabled: true}},
			want: []ocrypto.KeyType{"rsa:2048", "hpqt:xwing"},
		},
		{
			name: "mlkem on keeps pure mlkem",
			algs: []ocrypto.KeyType{"rsa:2048", "hpqt:xwing", "mlkem:768", "mlkem:1024"},
			cfg:  &access.KASConfig{Preview: access.Preview{HybridTDFEnabled: true, MLKEMTDFEnabled: true}},
			want: []ocrypto.KeyType{"rsa:2048", "hpqt:xwing", "mlkem:768", "mlkem:1024"},
		},
		{
			name: "mlkem on without hybrid keeps pure mlkem but drops hybrid",
			algs: []ocrypto.KeyType{"rsa:2048", "hpqt:xwing", "mlkem:768", "mlkem:1024"},
			cfg:  &access.KASConfig{Preview: access.Preview{MLKEMTDFEnabled: true}},
			want: []ocrypto.KeyType{"rsa:2048", "mlkem:768", "mlkem:1024"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := filterMechanismsByPreview(tc.algs, tc.cfg)
			assert.Equal(t, tc.want, got)
		})
	}
}

// fakeKeyManager is a minimal trust.KeyManager used to satisfy registration.
// SupportedAlgorithms now reads from registered metadata, not from the manager,
// so this type doesn't need to declare any algorithms itself.
type fakeKeyManager struct {
	name string
}

func (m *fakeKeyManager) Name() string { return m.name }
func (m *fakeKeyManager) Decrypt(_ context.Context, _ trust.KeyDetails, _, _ []byte) (ocrypto.ProtectedKey, error) {
	return nil, nil //nolint:nilnil // unused in this test
}

func (m *fakeKeyManager) DeriveKey(_ context.Context, _ trust.KeyDetails, _ []byte, _ elliptic.Curve) (ocrypto.ProtectedKey, error) {
	return nil, nil //nolint:nilnil // unused in this test
}

func (m *fakeKeyManager) GenerateECSessionKey(_ context.Context, _ string) (ocrypto.Encapsulator, error) {
	return nil, nil //nolint:nilnil // unused in this test
}
func (m *fakeKeyManager) Close() {}

// stubKeyIndex satisfies trust.KeyIndex without any backing storage.
type stubKeyIndex struct{}

func (stubKeyIndex) String() string       { return "stubKeyIndex" }
func (stubKeyIndex) LogValue() slog.Value { return slog.StringValue("stubKeyIndex") }
func (stubKeyIndex) FindKeyByAlgorithm(_ context.Context, _ string, _ bool) (trust.KeyDetails, error) {
	return nil, errors.New("not implemented")
}

func (stubKeyIndex) FindKeyByID(_ context.Context, _ trust.KeyIdentifier) (trust.KeyDetails, error) {
	return nil, errors.New("not implemented")
}
func (stubKeyIndex) ListKeys(_ context.Context) ([]trust.KeyDetails, error) { return nil, nil }
func (stubKeyIndex) ListKeysWith(_ context.Context, _ trust.ListKeyOptions) ([]trust.KeyDetails, error) {
	return nil, nil
}

func newBufferLogger() (*logger.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	handler := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	auditBase := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return &logger.Logger{
		Logger: slog.New(handler),
		Audit:  audit.CreateAuditLogger(*auditBase),
	}, buf
}

func TestLogSupportedMechanisms_EmitsInfoLine(t *testing.T) {
	l, buf := newBufferLogger()

	kd := trust.NewDelegatingKeyService(stubKeyIndex{}, l, nil)
	kd.RegisterKeyManagerCtxWithAlgorithms("fake", func(_ context.Context, _ *trust.KeyManagerFactoryOptions) (trust.KeyManager, error) {
		return &fakeKeyManager{name: "fake"}, nil
	}, []ocrypto.KeyType{"rsa:2048", "ec:secp256r1", "hpqt:xwing"})
	kd.SetDefaultMode("fake", "", nil)

	tests := []struct {
		name           string
		cfg            *access.KASConfig
		wantMechanisms []string
	}{
		{
			name:           "no preview flags",
			cfg:            &access.KASConfig{},
			wantMechanisms: []string{"rsa:2048"},
		},
		{
			name:           "both preview flags",
			cfg:            &access.KASConfig{Preview: access.Preview{ECTDFEnabled: true, HybridTDFEnabled: true, MLKEMTDFEnabled: true}},
			wantMechanisms: []string{"ec:secp256r1", "hpqt:xwing", "rsa:2048"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf.Reset()
			logSupportedMechanisms(context.Background(), l, kd, tc.cfg)

			data := strings.TrimSpace(buf.String())
			require.NotEmpty(t, data)
			lines := strings.Split(data, "\n")

			var found map[string]any
			for _, line := range lines {
				var record map[string]any
				require.NoError(t, json.Unmarshal([]byte(line), &record))
				if msg, _ := record["msg"].(string); msg == "kas trust mechanisms initialized" {
					found = record
					break
				}
			}
			require.NotNil(t, found, "expected log record with msg=kas trust mechanisms initialized")
			require.Equal(t, "INFO", found["level"])

			rawMechs, ok := found["mechanisms"].([]any)
			require.True(t, ok, "mechanisms field should be a slice")
			gotMechs := make([]string, 0, len(rawMechs))
			for _, m := range rawMechs {
				s, isStr := m.(string)
				require.True(t, isStr)
				gotMechs = append(gotMechs, s)
			}
			assert.Equal(t, tc.wantMechanisms, gotMechs)
		})
	}
}

func TestLogSupportedMechanisms_NilSafe(t *testing.T) {
	l, buf := newBufferLogger()
	kd := trust.NewDelegatingKeyService(stubKeyIndex{}, l, nil)

	// All three permutations of nil arg should be a no-op.
	logSupportedMechanisms(context.Background(), nil, kd, &access.KASConfig{})
	logSupportedMechanisms(context.Background(), l, nil, &access.KASConfig{})
	logSupportedMechanisms(context.Background(), l, kd, nil)

	assert.Empty(t, buf.String(), "no log output expected when args are nil")
}

// Compile-time check: fakeKeyManager satisfies trust.KeyManager.
var _ trust.KeyManager = (*fakeKeyManager)(nil)
