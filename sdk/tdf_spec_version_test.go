package sdk

import (
	"bytes"
	"io"
)

// Test_OffSpecSpecVersionIsReadFromContainer takes the off-spec
// tdf_spec_version name end to end: a real container whose spec version is
// recorded under that name loads, reports the version, and decrypts.
//
// Placement, precedence and value types are covered at the decoder level by
// TestManifest_UnmarshalJSON_SpecVersion. What only a container can show is
// that the fallback survives the rest of the read path -- LoadTDF, key unwrap
// and integrity verification -- rather than just the unmarshaller.
func (s *TDFSuite) Test_OffSpecSpecVersionIsReadFromContainer() {
	plaintext := make([]byte, 4242)
	for i := range plaintext {
		plaintext[i] = byte(i % 251)
	}

	kasInfoList := make([]KASInfo, len(s.kases))
	for i, ki := range s.kases {
		kasInfoList[i] = ki.KASInfo
		kasInfoList[i].PublicKey = ""
	}
	kasInfoList[0].Default = true

	original := &bytes.Buffer{}
	_, err := s.sdk.CreateTDF(original, bytes.NewReader(plaintext),
		WithKasInformation(kasInfoList...))
	s.Require().NoError(err)

	// Rewrite the manifest the way a writer built from the erroneous drafts
	// would have emitted it: no schemaVersion, the version under payload.
	rewritten := s.rewriteManifestRoot(original.Bytes(), func(manifest map[string]any) {
		version, ok := manifest["schemaVersion"].(string)
		s.Require().True(ok, "fixture should have been written with schemaVersion")
		s.Require().Equal(TDFSpecVersion, version)

		payload, ok := manifest["payload"].(map[string]any)
		s.Require().True(ok)
		payload["tdf_spec_version"] = version
		delete(manifest, "schemaVersion")
	})

	r, err := s.sdk.LoadTDF(bytes.NewReader(rewritten))
	s.Require().NoError(err)
	s.Require().Equal(TDFSpecVersion, r.Manifest().TDFVersion)

	decrypted := &bytes.Buffer{}
	n, err := io.Copy(decrypted, r)
	s.Require().NoError(err)
	s.Require().Equal(int64(len(plaintext)), n)
	s.Require().Equal(plaintext, decrypted.Bytes())
}
