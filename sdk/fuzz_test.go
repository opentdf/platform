package sdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
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
		for _, seg := range r.manifest.EncryptionInformation.IntegrityInformation.Segments {
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

func FuzzReadNanoTDF(f *testing.F) {
	sdk := newSDK()
	f.Add([]byte{ // seed from xtest
		// header
		0x4c, 0x31, 0x4c, // version
		0x00, 0x12, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x3a, 0x38, 0x30, 0x38, 0x30, 0x2f, 0x6b, 0x61, 0x73, // kas
		0x00, // binding_mode
		0x01, // symmetric_and_payload_config
		// policy
		0x02, 0x00, 0x68, 0xef, 0x70, 0x7b, 0x5f, 0x20, 0xb9, 0x0b, 0xf5, 0x96, 0xc3, 0xd7, 0x42, 0x85, 0x17, 0x6c, 0xd8, 0x98,
		0xad, 0x47, 0xc4, 0x9a, 0x81, 0x5f, 0x67, 0xc4, 0x0f, 0xff, 0x16, 0xbb, 0xf0, 0xf4, 0xcd, 0x31, 0xa5, 0xf6, 0x86, 0x59,
		0x3d, 0xf1, 0x53, 0x39, 0x3c, 0x3e, 0x16, 0xd8, 0xd2, 0x3b, 0x37, 0x50, 0x86, 0x6c, 0xfd, 0x2b, 0xce, 0xc7, 0x10, 0x89,
		0x66, 0x74, 0x22, 0xf0, 0x3f, 0x16, 0x7a, 0xed, 0x37, 0x93, 0x03, 0x30, 0xcc, 0x05, 0x21, 0xd2, 0x9e, 0x5d, 0xc3, 0x34,
		0xc5, 0x51, 0x60, 0xe6, 0xbf, 0x16, 0xdf, 0x92, 0xd0, 0x8d, 0xb0, 0xf0, 0x57, 0x6f, 0x7c, 0x37, 0xb9, 0x84, 0x44, 0xc7,
		0x64, 0x99, 0x6a, 0xd3, 0x6e, 0xaa, 0x04,
		0xf3, 0x18, 0xe9, 0x0b, 0xd0, 0xdc, 0x05, 0x38, // gmac_binding
		// ephemeral_key
		0x03, 0x66, 0x95, 0xd9, 0x3b, 0x84, 0xee, 0xc5, 0x65, 0xc1, 0x13, 0x1c, 0x94, 0xc6, 0x00, 0x8b, 0xcb, 0x6a, 0xf5, 0x90,
		0xd5, 0x0d, 0x90, 0xc5, 0xf4, 0xe5, 0x96, 0x56, 0xb2, 0xd9, 0x4a, 0x9b, 0x51,
		// payload
		0x00, 0x00, 0x8f, // length
		0x54, 0x2b, 0x53, // iv
		// ciphertext
		0xce, 0x35, 0x1d, 0x0a, 0xd9, 0x7a, 0x81, 0xb5, 0xda, 0x93, 0x39, 0xd5, 0xa2, 0x42, 0x22, 0xa3, 0x64, 0x97, 0x2e, 0x33,
		0x41, 0x84, 0x12, 0x26, 0x81, 0xf5, 0x10, 0xc9, 0xf4, 0x94, 0xb8, 0x55, 0x52, 0x24, 0xeb, 0xaf, 0x89, 0xc3, 0x24, 0x7e,
		0x32, 0xcf, 0xd5, 0xda, 0xa2, 0xcb, 0x98, 0x67, 0x71, 0xc3, 0xa5, 0xf6, 0xa8, 0xe3, 0x4e, 0x64, 0x23, 0x2e, 0x40, 0xee,
		0x2e, 0xd9, 0xa4, 0x97, 0x87, 0x83, 0xd4, 0xe7, 0x11, 0xfe, 0xdb, 0xf4, 0x42, 0xc1, 0x71, 0x3b, 0x5a, 0x07, 0x01, 0x76,
		0xb2, 0xf8, 0x48, 0x23, 0x2d, 0xb3, 0x53, 0x61, 0x98, 0x39, 0x13, 0x7b, 0x45, 0xcd, 0x55, 0x76, 0xbe, 0x71, 0x3a, 0x88,
		0xf3, 0xce, 0xec, 0xc2, 0x68, 0x7d, 0xfd, 0x38, 0x4d, 0x49, 0xef, 0x57, 0x9a, 0xc7, 0x45, 0x81, 0xe4, 0x6f, 0xab, 0x4b,
		0x50, 0xa2, 0x43, 0x08, 0x71, 0x78, 0x43, 0xa2,
		0x66, 0x8e, 0x2b, 0xfd, 0x64, 0xc3, 0xed, 0x09, 0x1f, 0xa6, 0xe8, 0xa2, // mac
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		writer := bytes.NewBuffer(nil)
		_, err := sdk.ReadNanoTDF(writer, bytes.NewReader(data))

		require.Error(t, err) // will always err due to no server running
		require.Equal(t, 0, writer.Len())
	})
}

func FuzzReadPolicyBody(f *testing.F) {
	pb := &PolicyBody{
		mode: 0,
		rp: remotePolicy{
			url: ResourceLocator{
				protocol: 0,
				body:     "example.com",
			},
		},
	}
	f.Add(writeBytes(pb.writePolicyBody))
	pb = &PolicyBody{
		mode: 1,
		ep: embeddedPolicy{
			lengthBody: 3,
			body:       []byte("foo"),
		},
	}
	f.Add(writeBytes(pb.writePolicyBody))

	f.Fuzz(func(t *testing.T, data []byte) {
		pb = &PolicyBody{}
		err := pb.readPolicyBody(bytes.NewReader(data))
		if err != nil {
			assert.Zerof(t, *pb, "unexpected %v", *pb)
			return
		}
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
