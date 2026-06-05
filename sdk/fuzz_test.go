package sdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/sdk/auth"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeBytes(writerFunc func(io.Writer) error) []byte {
	writer := bytes.NewBuffer(nil)
	_ = writerFunc(writer)
	return writer.Bytes()
}

func newSDK() *SDK {
	key, _ := ocrypto.NewRSAKeyPair(tdf3KeySize)
	cfg := &config{
		logger:        slog.Default(),
		kasSessionKey: &key,
	}
	sdk := &SDK{
		config:      *cfg,
		kasKeyCache: newKasKeyCache(),
		tokenSource: &fakeTokenSource{},
	}
	return sdk
}

type fakeTokenSource struct{}

func (f *fakeTokenSource) AccessToken(_ context.Context, _ *http.Client) (auth.AccessToken, error) {
	return "fake token", nil
}

func (f *fakeTokenSource) MakeToken(func(jwk.Key) ([]byte, error)) ([]byte, error) {
	return []byte("fake token"), nil
}

type fakeWriter struct{}

func (fw *fakeWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func unverifiedBase64Bytes(str string) []byte {
	b, _ := base64.StdEncoding.DecodeString(str)
	return b
}

func FuzzLoadTDF(f *testing.F) {
	mockWellKnown := newMockWellKnownService(createWellKnown(nil), nil)
	sdk := newSDK()
	sdk.wellknownConfiguration = mockWellKnown
	f.Add(writeBytes(func(writer io.Writer) error {
		reader := bytes.NewReader([]byte("AAA"))
		_, err := sdk.CreateTDF(writer, reader, func(tdfConfig *TDFConfig) error {
			tdfConfig.kasInfoList = []KASInfo{{
				URL:       "example.com",
				PublicKey: mockRSAPublicKey1,
				Default:   true,
			}}
			return nil
		})
		require.NoError(f, err)
		return err
	}))
	// seed with large manifest allocation up front
	f.Add(unverifiedBase64Bytes("UEsDBC0ACAAAAH11LzEAAAAAAAAAAAAAAAAJAAAAM" +
		"C5wYXlsb2Fk5LJYrTiapi/CUQ0dlqMU0/VmunX+qRIyQghasf6aEVBLBwgke7o5HwAAAB8A" +
		"AABQSwMELQAIAAAAfXUvMQAAAAAAAAAAAAAAAA8AAAAwLm1hbmlmZXN0Lmpzb257ImVOY3J" +
		"5cHRpb25JbmZvcm1hdGlvbiI6eyJ0eXBlIjoic3BsaXQiLCJwb2xpY3kiOiJleUoxZFdsa0" +
		"lqb2lZakF3TW1WaU9USXROV0l4TkMweE1XVm1MVGt4TW1NdFlXRTFZalprWlRjMVlUQmpJa" +
		"XdpWW05a2VTSTZleUprWVhSaFFYUjBjbWx5ZFhSbGN5STZiblZzYkN3aVpHbHpjMlZ0SWpw" +
		"dWRXeHNmWDA9Iiwia2V5QWNjZXNzIjpbeyJ0eXBlIjoid3JhcHBlZCIsInVybCI6ImV4YW1" +
		"wbGUuY29tIiwicHJvdG9jb2wiOiJrYXMiLCJ3cmFwcGVkS2V5IjoiV1dZait3anNMQmtrU2" +
		"FjTzZ2dEpJaTBLMUJQMVhtT2lzcFNrdm8wRm5QV0ZLM050UTVzN3YwOVpqQ05NV0JRK1VPa" +
		"VhUTVNWa1JkNUdsTHlMblg3bjY4dDBmSDk0RnMyTnRjcFJwMSt6YStjdzVGRldFQy9uQUJp" +
		"TmtPdldLeHdqeG5YQ1pEazZ4U3o1ZHdCT1MraUVCYXJ6WGMzR3oxR2JYcm5Ka0YvaitUUDR" +
		"rbTJUYUpXN0cybFJaQ0J6T1M5RkpoSEFIcFBIcFF4V2tNK2FuZjJ1WExRV1UxT00vaHFVRz" +
		"VFUG9nR0pYM3MxaVRmek4xNFhiczU5TmYyOU1rc284VjhJSnNOWVRPblBIejY4Q3VvOGdjc" +
		"XZHd3J0a3FKQmlmYVM3N1FRQWxwUTcrSU9GME9ZSjh1WTZLZG1najltSU1aRUVaYkI3V2hO" +
		"blNBbG9paWZBPT0iLCJwb2xpY3lCaW5kaW5nIjp7ImFsZyI6IkhTMjU2IiwiaGFzaCI6Ilp" +
		"UY3pZMkV5WkdReVkySTJNRGN4WmpnellXVTVNRGsxWXpnNU5XWXhOalUwWVRjNE5tTXpPV1" +
		"EwTW1JM05qQmxOemxsTmpWaVltWTRZalUyWkdNd013PT0ifX1dLCJtZXRob2QiOnsiYWxnb" +
		"3JpdGhtIjoiQUVTLTI1Ni1HQ00iLCJpdiI6IiIsImlzU3RyZWFtYWJsZSI6dHJ1ZX0sImlu" +
		"dGVncml0eUluZm9ybWF0aW9uIjp7InJvb3RTaWduYXR1cmUiOnsiYWxnIjoiSFMyNTYiLCJ" +
		"zaWciOiJNRFZqTURReE1EWmtNR00wWlRRMllUZG1PRFJrWVRJM09UZGlPREk1WVRWak5EVX" +
		"hPRGs0TkRreE1HWTFaV1kxTXpKbVpHWmtZMlkwWWprek0yVmhOZz09In0sInNlZ21lbnRIY" +
		"XNoQWxnIjoiR01BQyIsInNlZ21lbnRTaXplRGVmYXVsdCI6MjA5NzE1MiwiZW5jcnlwdGVk" +
		"U2VnbWVudFNpemVEZWZhdWx0IjoyMDk3MTgwLCJzZWdtZW50cyI6W3siaGFzaCI6IlpETm1" +
		"OVFkyWW1FM05XWmxZVGt4TWpNeU5ESXdPRFZoWWpGbVpUbGhNVEU9Iiwic2VnbWVudFNpem" +
		"UiOjMsImVuY3J5cHRlZFNlZ21lbnRTaXplIjozMX1dfX0sInBheWxvYWQiOnsidHlwZSI6I" +
		"nJlZmVyZW5jZSIsInVybCI6IjAucGF5bG9hZCIsInByb3RvY29sIjoiemlwIiwibWltZVR5" +
		"cGUiOiJhcHBsaWNhdGlvbi9vY3RldC1zdHJlYW0iLCJpc0VuY3J5cHRlZCI6dHJ1ZX19UEs" +
		"HCALoriwCBQAAAgUAAFBLAQItAC0ACAAAAH11LzEke7o5HwAAAB8AAAAJAAAAAAAAAAAAAA" +
		"AAAAAAAAAwLnBheWxvYWRQSwECLQAtAAgAAAB9dS8xAuiuLAIE///tBQAADwAAAAAAAAAAA" +
		"AAAAABWAAAAMC5tYW5pZmVzdC5qc29uUEsFBgAAAAACAAIAdAAAAJUFAAAAAA=="))
	// small manifest lies about payload sizes, instead defines maximum values
	f.Add(unverifiedBase64Bytes("UEsDBC0ACAAAAF2CRjEAAAAAAAAAAAAAAAAJAAAAM" +
		"C5wYXlsb2FkTWCxOyxyaAcOOlXw7VBpYSZPdIIa1yc0DEIZVk+Cn1BLBwgrOASPHwAAAB8A" +
		"AABQSwMELQAIAAAAXYJGMQAAAAAAAAAAAAAAAA8AAAAwLm1hbmlmZXN0Lmpzb257ImVuY3J" +
		"5cHRpb25JbmZvcm1hdGlvbiI6eyJ0eXBlIjoic3BsaXQiLCJwb2xpY3kiOiJleUoxZFdsa0" +
		"lqb2lZVGcxT0dKa05qTXRObU0yWWkweE1XVm1MV0UxTjJFdE1EQXdZekk1TVRabE9HVTFJa" +
		"XdpWW05a2VTSTZleUprWVhSaFFYUjBjbWxpZFhSbGN5STZiblZzYkN3aVpHbHpjMlZ0SWpw" +
		"dWRXeHNmWDA9Iiwia2V5QWNjZXNzIjpbeyJ0eXBlIjoid3JhcHBlZCIsInVybCI6ImV4YW1" +
		"wbGUuY29tIiwicHJvdG9jb2wiOiJrYXMiLCJ3cmFwcGVkS2V5IjoiQUVab1E0ZFpjSlpxTl" +
		"h3L0tEd20zQ1J1YUxrRVBXeEVuQnBwUWZhTzZ1c2k1bWxBVnR4SnZHYTliU3lpc0taWFVnU" +
		"kVpZDdwVzRQeTdSb2E1MWxXOFA0Mk1sYlZEdlJiL1g0NlBwemUrbmIzQlMxS05yWVBwakNU" +
		"YitaUkdFNzByRHpMNXRWYmNVRzN1YnhNREJGd3NQMXM0cTd6OGhjVHpodVZpSEZ4SVdRcUd" +
		"rYzNEM01QRjU2NzFneUlwOWxyVWZsSnZxZGFGRlZmejEyRFJhWGVRYVRVMDdDN21XZi9IRj" +
		"ltaHlWZmVMazUxLzJlQkIvYkcyOUIvc0IzKzVWKy9YWFZZeXNzc0s3YzU0UVByd1BOYzBZN" +
		"HFvWFgwMWY3QWcyY2JWaFJmMjluOXV0RU81aWFUUmRpWVFuNXdYeTBtSFZGTVRIWlVFYUg4" +
		"UmhCTHpsQVNRPT0iLCJwb2xpY3lCaW5kaW5nIjp7ImFsZyI6IkhTMjU2IiwiaGFzaCI6Ilp" +
		"XWXlPREEzT0RFNFlqZ3pZemcyTW1Vek5tWmhNREEyTnpCbE9XWTVZemRtWXpZNE9HUmlOal" +
		"U0TjJZMll6WmpZVE13WWpoaU9UQXlaR0UxTlRjd05BPT0ifX1dLCJtZXRob2QiOnsiYWxnb" +
		"3JpdGhtIjoiQUVTLTI1Ni1HQ00iLCJpdiI6IiIsImlzU3RyZWFtYWJsZSI6dHJ1ZX0sImlu" +
		"dGVncml0eUluZm9ybWF0aW9uIjp7InJvb3RTaWduYXR1cmUiOnsiYWxnIjoiSFMyNTYiLCJ" +
		"zaWciOiJOekZrTWpKaU16RTFPRGszWmpBeE9UZzBNVE0xWmpnd09HTTVPV0l5TTJVME5UTX" +
		"paR1ppTWpsbFlUYzFNR1EzTm1VMlpXRmlPRFpoWXprek5ESXdNZz09In0sInNlZ21lbnRIY" +
		"XNoQWxnIjoiR01BQyIsInNlZ21lbnRTaXplRGVmYXVsdCI6MjA5NzE1MiwiZW5jcnlwdGVk" +
		"U2VnbWVudFNpemVEZWZhdWx0IjoyMDk3MTgwLCJzZWdtZW50cyI6W3siaGFzaCI6Ik5qRXl" +
		"OalJtTnpRNE1qRmhaRGN5TnpNME1HTTBNakU1TlRZMFpqZ3lPV1k9Iiwic2VnbWVudFNpem" +
		"UiOjMsImVuY3J5cHRlZFNlZ21lbnRTaXplIjozMX1dfX0sInBheWxvYWQiOnsidHlwZSI6I" +
		"nJlZmVyZW5jZSIsInVybCI6IjAucGF5bG9hZCIsInByb3RvY29sIjoiemlwIiwibWltZVR5" +
		"cGUiOiJhcHBsaWNhdGlvbi9vY3RldC1zdHJlYW0iLCJpc0VuY3J5cHRlZCI6dHJ1ZX19UEs" +
		"HCDH2fQf//////////1BLAQItAC0ACAAAAF2CRjErOASPHwAAAB8AAAAJAAAAAAAAAAAAAA" +
		"AAAAAAAAAwLnBheWxvYWRQSwECLQAtAAgAAABdgkYxMfZ9BwIFAAACBQAADwAAAAAAAAAAA" +
		"AAAAABWAAAAMC5tYW5pZmVzdC5qc29uUEsFBgAAAAACAAIAdAAAAJUFAAAAAA=="))
	// fuzzed failure from above seed with size overflow, will fail on WriteTo action
	f.Add(unverifiedBase64Bytes("UEsDBC0ACAAAAF2uLzEAAAAAAAAAAAAAAAAJAAAAM" +
		"C5wYXlsb2FkThU3KcYXLpEEfhvsuHrxvIer1/zmhcGctLZ6o0RNOFBLBwhp296fHwAAAB8A" +
		"AABQSwMELQAIAAAAXa4vMQAAAAAAAAAAAAAAAA8AAAAwLm1hbmlmZXN0Lmpzb257ImVuY3J" +
		"5cHRpb25JbmZvcm1hdGlvbiI6eyJ0eXBlIjoic3BsaXQiLCJwb2xpY3kiOiJleUoxZFdsa0" +
		"lqb2lOalpsTkRJME5qQXROV0kxTUMweE1XVm1MVGt6Wm1JdE1EQXdZekk1TVRabE9HVTFJa" +
		"XdpWW05a2VTSTZleUprWVhSaFFYUjBjbWxpZFhSbGN5STZiblZzYkN3aVpHbHpjMlZ0SWpw" +
		"dWRXeHNmWDA9Iiwia2V5QWNjZXNzIjpbeyJ0eXBlIjoid3JhcHBlZCIsInVybCI6ImV4YW1" +
		"wbGUuY29tIiwicHJvdG9jb2wiOiJrYXMiLCJ3cmFwcGVkS2V5IjoiSlFGUW1qVWlFdHdwOW" +
		"Q1S3QvaythQmY0djA4akVSUjNhRnBldmV5cHVLdXhQODU1TUVRVFZ2R2k5VG9sdnBROUpne" +
		"GRxdTNRdWVEMFp5SG9VZTM1cEU4U05wSCtEOXJjemFTMTh6MDVZME9KVUxyTEpwWUQrVDFa" +
		"SWIyQ29razlsT0ZJalV6cUpqWkpPUE1GdDVsRjhEUlhSeDVGZm1oUEFKQkx4UmprTmpZUnJ" +
		"lbWI4UW5wWFNXcWVDREZiYnJ4azNEcVpKaTdCODllYjlzbjFBNUZmUEk3Vjkwa0crSEN6Kz" +
		"RVcGhNUzM0R1c5MXNTSkZpZ0ZJM2VBUEhiTTZoRnU2QndsZjdKK3hTUFZtd1FCdVVXMUxwe" +
		"HFDQ3dkNFRxT3JPVXplWEE4aFJTdncvNW82VUlLZGpFUEhua0s1dXVwbStuTENBcmRONFA5" +
		"L2JkS0h3ZXR3PT0iLCJwb2xpY3lCaW5kaW5nIjp7ImFsZyI6IkhTMjU2IiwiaGFzaCI6Ik5" +
		"XUTROVEl5TW1WaU1tWTFZMlJqT0dJeFpUQTJOakk0WVdFME9XRmhaV05qTnpjMk1XSXdNVF" +
		"U0WldRNVptTm1ZekJqTnpsbU5USTJZV0poTjJaall3PT0ifX1dLCJtZXRob2QiOnsiYWxnb" +
		"3JpdGhtIjoiQUVTLTI1Ni1HQ00iLCJpdiI6IiIsImlzU3RyZWFtYWJsZSI6dHJ1ZX0sImlu" +
		"dGVncml0eUluZm9ybWF0aW9uIjp7InJvb3RTaWduYXR1cmUiOnsiYWxnIjoiSFMyNTYiLCJ" +
		"zaWciOiJPRFV5WWpKaU9HVmlaR1V3T0RFMk5HRmtNMkV5T0dObU9ETXdNR0k1WkRWa01HTm" +
		"lNRFk1WlRBMFkyRXpNRFZtTm1Sak1UWmxZVGcxT0RjMlkyRXlNdz09In0sInNlZ21lbnRIY" +
		"XNoQWxnIjoiR01BQyIsInNlZ21lbnRTaVplRGVmYXVsdCI6MjA5NzE1MiwiZW5jcnlwdGVk" +
		"U2VnbWVudFNpemVEZWZhdWx0IjoyMDk3MTgwLCJzZWdtZW50cyI6W3siaGFzaCI6IlltTTR" +
		"OMkZpWkRkbVkyVTJPRFZqTVRsallqUmlOamRoWVRNME5EUmtNemc9Iiwic2VnbWVudFNpem" +
		"UiOjMsImVuY3J5cHRlZFNlZ21lbnRTaXplIjotMX1dfX0sInBheWxvYWQiOnsidHlwZSI6I" +
		"nJlZmVyZW5jZSIsInVybCI6IjAucGF5bG9hZCIsInByb3RvY29sIjoiemlwIiwibWltZVR5" +
		"cGUiOiJhcHBsaWNhdGlvbi9vY3RldC1zdHJlYW0iLCJpc0VuY3J5cHRlZCI6dHJ1ZX19UEs" +
		"HCNSOqYACBQAAAgUAAFBLAQItAC0ACAAAAF2uLzFp296fHwAAAB8AAAAJAAAAAAAAAAAAAA" +
		"AAAAAAAAAwLnBheWxvYWRQSwECLQAtAAgAAABdri8x1I6pgAIFAAACBQAADwAAAAAAAAAAA" +
		"AAAAABWAAAAMC5tYW5pZmVzdC5qc29uUEsFBgAAAAACAAIAdAAAAJUFAAAAAA=="))
	// large segment sizes
	// commented out because payload is too large to provide an efficient seed context - only use for manual testing
	/*f.Add(writeBytes(func(writer io.Writer) error {
		size := math.MaxInt32 / 100 // just small enough to allow allocation for writing
		reader := bytes.NewReader(make([]byte, size))
		_, err := sdk.CreateTDF(writer, reader, func(tdfConfig *TDFConfig) error {
			tdfConfig.kasInfoList = []KASInfo{{
				URL:       "example.com",
				PublicKey: mockRSAPublicKey1,
				Default:   true,
			}}
			tdfConfig.defaultSegmentSize = int64(size)
			return nil
		})
		require.NoError(f, err)
		return err
	}))*/

	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := sdk.LoadTDF(bytes.NewReader(data))
		if err != nil {
			assert.Nil(t, r)
			return
		}
		assert.NotNil(t, r)

		// set fake payloadKey and associated data to avoid grpc request
		r.payloadKey = make([]byte, kKeySize)
		_, _ = rand.Read(r.payloadKey)
		gcm, err := ocrypto.NewAESGcm(r.payloadKey)
		require.NoError(t, err)
		for _, seg := range r.manifest.Segments {
			r.payloadSize += seg.Size
		}
		r.unencryptedMetadata = []byte{}
		r.aesGcm = gcm

		// validate TDF is safe to write, the segment sizes will result in allocations for example
		_, _ = r.WriteTo(&fakeWriter{})
		// DataAttributes builds a slice of attributes
		_, _ = r.DataAttributes()
	})
}

func FuzzNewResourceLocatorFromReader(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00}) // zero size
	f.Add([]byte{0x00, 0xFF, 0x00}) // max size
	// example self encoded
	rl, _ := NewResourceLocator("https://example.com")
	f.Add(writeBytes(rl.writeResourceLocator))

	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := NewResourceLocatorFromReader(bytes.NewReader(data))
		if err != nil {
			assert.Nil(t, r)
			return
		}
		require.NotNil(t, r)
	})
}

var attributeSeeds = []string{
	// select seeds taken from granter_test.go
	"http://e/attr/a/value/1",
	"http://e/attr/1/value/one",
	"http://e/attr/value/value/one",
	"http://e/attr/a/value/%20",
	// error cases
	"http://e/attr",
	"hxxp://e/attr/a",
	"https://a/attr/%😁",
	"http://e/attr/a/value/b",
	// fuzzer discovered panic cases
	"http://0/attr//0/value/",
	"http://e/attr///value/0",
	"http://e/attr////value/0",
	"http://0/attr/0//value/0",
	"http://0/attr//0/value/0",
	"http://0/attr/0/0/value/0",
}

func FuzzNewAttributeNameFQN(f *testing.F) {
	for _, s := range attributeSeeds {
		f.Add(s)
	}

	f.Fuzz(func(_ *testing.T, data string) {
		fqn, err := NewAttributeNameFQN(data)
		if err == nil { // if possible validate additional functionality does not result in failure
			_ = fqn.Authority()
			_ = fqn.Name()
			_ = fqn.Prefix()
			_ = fqn.String()
		}
	})
}

func FuzzNewAttributeValueFQN(f *testing.F) {
	for _, s := range attributeSeeds {
		f.Add(s)
	}

	f.Fuzz(func(_ *testing.T, data string) {
		fqn, err := NewAttributeValueFQN(data)
		if err == nil {
			_ = fqn.Authority()
			_ = fqn.Name()
			_ = fqn.Prefix()
			_ = fqn.String()
		}
	})
}
