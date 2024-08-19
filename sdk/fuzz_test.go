package sdk

import (
	"bytes"
	"encoding/base64"
	"io"
	"testing"

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
	}
	return sdk
}

func unverifiedBase64Bytes(str string) []byte {
	b, _ := base64.StdEncoding.DecodeString(str)
	return b
}

func FuzzLoadTDF(f *testing.F) {
	sdk := newSDK()
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
	// seed with large manifest allocation
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

	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := sdk.LoadTDF(bytes.NewReader(data))
		if err != nil {
			assert.Nil(t, r)
			return
		}
		assert.NotNil(t, r)
		// TODO fuzz r somewhat
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
		switch pb.mode {
		case policyTypeRemotePolicy:
			assert.Zero(t, pb.ep)
			assert.NotZero(t, pb.rp)
		case policyTypeEmbeddedPolicyEncrypted, policyTypeEmbeddedPolicyEncryptedPolicyKeyAccess, policyTypeEmbeddedPolicyPlainText:
			assert.NotZero(t, pb.ep)
			assert.Zero(t, pb.rp)
		default:
			assert.Fail(t, "undefined policy mode", "policy mode: [%d]", pb.mode)
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
