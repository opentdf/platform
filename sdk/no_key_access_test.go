package sdk

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requestRecorder records every outbound request and answers none of them.
type requestRecorder struct {
	mu   sync.Mutex
	urls []string
}

func (r *requestRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.urls = append(r.urls, req.Method+" "+req.URL.String())
	r.mu.Unlock()
	return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
}

func (r *requestRecorder) requests() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.urls...)
}

const keyAccessTestKAS = "https://kas.example.com/"

// fixedKeyTDF returns a TDF whose payload, segment hash, root signature and
// (optionally) payload-key assertion are all made under one fixed key, with
// the given key access objects. edit, if set, may rewrite the manifest JSON.
func fixedKeyTDF(t *testing.T, plaintext []byte, kaos []KeyAccess, withAssertion bool, edit func(map[string]any)) []byte {
	t.Helper()
	key := make([]byte, kKeySize)
	gcm, err := ocrypto.NewAESGcm(key)
	require.NoError(t, err)
	ciphertext, err := gcm.Encrypt(plaintext)
	require.NoError(t, err)
	segSig, err := segmentIntegrity(ciphertext, key, SegmentGMAC, false)
	require.NoError(t, err)
	aggregate := []byte(segSig)
	rootSig, err := rootIntegrity(aggregate, key, RootHS256, false)
	require.NoError(t, err)

	var assertions []Assertion
	if withAssertion {
		assertions, err = signAssertions(aggregate, []AssertionConfig{{
			ID: "payload-key-assertion", Type: BaseAssertion, Scope: TrustedDataObjScope, AppliesToState: Unencrypted,
			Statement: Statement{Format: "text", Schema: "text", Value: "v"},
		}}, key, false)
		require.NoError(t, err)
	}

	m := Manifest{
		EncryptionInformation: EncryptionInformation{
			KeyAccessType: kSplitKeyType,
			Policy:        string(ocrypto.Base64Encode([]byte(`{"uuid":"00000000-0000-0000-0000-000000000000","body":{"dataAttributes":[],"dissem":[]}}`))),
			KeyAccessObjs: kaos,
			IntegrityInformation: IntegrityInformation{
				RootSignature:           RootSignature{Algorithm: "HS256", Signature: string(ocrypto.Base64Encode([]byte(rootSig)))},
				SegmentHashAlgorithm:    "GMAC",
				DefaultSegmentSize:      int64(len(plaintext)),
				DefaultEncryptedSegSize: int64(len(ciphertext)),
				Segments: []Segment{{
					Hash: string(ocrypto.Base64Encode([]byte(segSig))), Size: int64(len(plaintext)), EncryptedSize: int64(len(ciphertext)),
				}},
			},
		},
		Payload:    Payload{Type: "reference", URL: "0.payload", Protocol: "zip", MimeType: "text/plain", IsEncrypted: true},
		Assertions: assertions,
		TDFVersion: TDFSpecVersion,
	}
	manifest, err := json.Marshal(m)
	require.NoError(t, err)
	if edit != nil {
		var generic map[string]any
		require.NoError(t, json.Unmarshal(manifest, &generic))
		edit(generic)
		manifest, err = json.Marshal(generic)
		require.NoError(t, err)
	}

	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, f := range []struct {
		name string
		body []byte
	}{{"0.payload", ciphertext}, {"0.manifest.json", manifest}} {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: f.name, Method: zip.Store})
		require.NoError(t, err)
		_, err = w.Write(f.body)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return out.Bytes()
}

// readerFor loads tdf with an SDK whose HTTP client records every request
// and answers none.
func readerFor(t *testing.T, tdf []byte, opts ...TDFReaderOption) (*Reader, *requestRecorder) {
	t.Helper()
	recorder := &requestRecorder{}
	s := SDK{
		conn:        &ConnectRPCConnection{Client: &http.Client{Transport: recorder}},
		tokenSource: getTokenSource(t),
	}
	opts = append([]TDFReaderOption{WithKasAllowlist([]string{keyAccessTestKAS})}, opts...)
	r, err := s.LoadTDF(bytes.NewReader(tdf), opts...)
	require.NoError(t, err, "loading only parses the manifest")
	return r, recorder
}

// encryptionInformation returns the manifest's encryptionInformation object.
func encryptionInformation(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	ei, ok := m["encryptionInformation"].(map[string]any)
	require.True(t, ok)
	return ei
}

func TestDecryptWithoutKeyAccessObjectsIsRefused(t *testing.T) {
	plaintext := []byte("fixed-key plaintext")

	reads := map[string]func(r *Reader) ([]byte, error){
		"WriteTo": func(r *Reader) ([]byte, error) {
			var out bytes.Buffer
			_, err := r.WriteTo(&out)
			return out.Bytes(), err
		},
		"Read": func(r *Reader) ([]byte, error) {
			buf := make([]byte, len(plaintext))
			n, err := r.Read(buf)
			return buf[:n], err
		},
		"ReadAt": func(r *Reader) ([]byte, error) {
			buf := make([]byte, len(plaintext))
			n, err := r.ReadAt(buf, 0)
			return buf[:n], err
		},
		"UnencryptedMetadata": func(r *Reader) ([]byte, error) { return r.UnencryptedMetadata() },
	}

	for name, tc := range map[string]struct {
		edit          func(*testing.T, map[string]any)
		withAssertion bool
		opts          []TDFReaderOption
	}{
		"empty, assertions verified":   {withAssertion: true},
		"empty, verification disabled": {opts: []TDFReaderOption{WithDisableAssertionVerification(true)}},
		"null":                         {edit: func(t *testing.T, m map[string]any) { encryptionInformation(t, m)["keyAccess"] = nil }},
		"absent":                       {edit: func(t *testing.T, m map[string]any) { delete(encryptionInformation(t, m), "keyAccess") }},
	} {
		t.Run(name, func(t *testing.T) {
			var edit func(map[string]any)
			if tc.edit != nil {
				edit = func(m map[string]any) { tc.edit(t, m) }
			}
			tdf := fixedKeyTDF(t, plaintext, []KeyAccess{}, tc.withAssertion, edit)

			valid, err := IsValidTdf(bytes.NewReader(tdf))
			if name == "null" {
				require.ErrorIs(t, err, ErrInvalidPerSchema, "the schema has always refused a null list")
			} else {
				require.NoError(t, err, "the manifest is structurally valid")
				assert.True(t, valid)
			}

			for readName, read := range reads {
				r, recorder := readerFor(t, tdf, tc.opts...)
				got, err := read(r)
				require.ErrorIs(t, err, ErrNoKeyAccessObjects, readName)
				assert.Contains(t, err.Error(), "no key access objects", readName)
				assert.Empty(t, recorder.requests(), "%s: no KAS or other request may be made", readName)
				assert.Empty(t, got, "%s: no plaintext may be released", readName)
			}
		})
	}

	t.Run("one key access object asks the KAS", func(t *testing.T) {
		kao := KeyAccess{
			KeyType: kWrapped, KasURL: keyAccessTestKAS, Protocol: kKasProtocol,
			WrappedKey:    string(ocrypto.Base64Encode([]byte("wrapped"))),
			PolicyBinding: PolicyBinding{Alg: "HS256", Hash: "aGFzaA=="},
		}
		r, recorder := readerFor(t, fixedKeyTDF(t, plaintext, []KeyAccess{kao}, true, nil))
		var out bytes.Buffer
		_, err := r.WriteTo(&out)
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrNoKeyAccessObjects)
		assert.NotEmpty(t, recorder.requests(), "the reader asks the KAS for the key")
		assert.Empty(t, out.Bytes())
	})
}

func TestBuildKeyRefusesWhenNoSplitWasFound(t *testing.T) {
	r := &Reader{manifest: Manifest{EncryptionInformation: EncryptionInformation{
		KeyAccessObjs: []KeyAccess{{KasURL: keyAccessTestKAS}},
	}}}
	err := r.buildKey(t.Context(), nil)
	require.ErrorIs(t, err, ErrNoKeyAccessObjects)
	assert.Nil(t, r.payloadKey)
}
