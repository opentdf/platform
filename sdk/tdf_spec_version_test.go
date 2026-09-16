package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"hash/crc32"
	"io"

	"github.com/opentdf/platform/sdk/internal/zipstream"
)

// renameSpecVersionToOffSpec rewrites a container's manifest the way a writer
// built from the erroneous drafts would have emitted it: schemaVersion removed,
// the same value recorded as tdf_spec_version under payload. It returns the
// rewritten archive and the version it moved.
//
// Re-serializing the manifest without re-signing leaves a container that is
// still internally consistent, since the root signature covers the segment
// hashes rather than the JSON encoding.
func (s *TDFSuite) renameSpecVersionToOffSpec(tdfBytes []byte) ([]byte, string) {
	s.T().Helper()

	zipReader, err := zipstream.NewReader(bytes.NewReader(tdfBytes))
	s.Require().NoError(err)

	manifestBytes, err := zipReader.ReadAllFileData(zipstream.TDFManifestFileName, 10*oneMB)
	s.Require().NoError(err)

	payloadSize, err := zipReader.ReadFileSize(zipstream.TDFPayloadFileName)
	s.Require().NoError(err)
	payload, err := zipReader.ReadFileData(zipstream.TDFPayloadFileName, 0, payloadSize)
	s.Require().NoError(err)

	var manifest map[string]any
	s.Require().NoError(json.Unmarshal(manifestBytes, &manifest))

	version, ok := manifest["schemaVersion"].(string)
	s.Require().True(ok, "fixture should have been written with schemaVersion")
	payloadObj, ok := manifest["payload"].(map[string]any)
	s.Require().True(ok)
	payloadObj["tdf_spec_version"] = version
	delete(manifest, "schemaVersion")

	rewritten, err := json.Marshal(manifest)
	s.Require().NoError(err)

	ctx := context.Background()
	writer := zipstream.NewSegmentTDFWriter(1)
	defer func() { s.Require().NoError(writer.Close()) }()

	out := &bytes.Buffer{}
	header, err := writer.WriteSegment(ctx, 0, uint64(len(payload)), crc32.ChecksumIEEE(payload))
	s.Require().NoError(err)
	out.Write(header)
	out.Write(payload)

	final, err := writer.Finalize(ctx, rewritten)
	s.Require().NoError(err)
	out.Write(final)

	return out.Bytes(), version
}

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

	rewritten, version := s.renameSpecVersionToOffSpec(original.Bytes())
	s.Require().Equal(TDFSpecVersion, version)

	r, err := s.sdk.LoadTDF(bytes.NewReader(rewritten))
	s.Require().NoError(err)
	s.Require().Equal(TDFSpecVersion, r.Manifest().TDFVersion)

	decrypted := &bytes.Buffer{}
	n, err := io.Copy(decrypted, r)
	s.Require().NoError(err)
	s.Require().Equal(int64(len(plaintext)), n)
	s.Require().Equal(plaintext, decrypted.Bytes())
}
