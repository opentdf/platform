package archive

import "io"

type TDFWriter struct {
	archiveWriter *Writer
	stats         Stats
}

type Stats struct {
	ManifestSize, PayloadSize int64
}

// NewTDFWriter Create tdf writer instance.
func NewTDFWriter(writer io.Writer) *TDFWriter {
	tdfWriter := TDFWriter{}
	tdfWriter.archiveWriter = NewWriter(writer)

	return &tdfWriter
}

// SetPayloadSize Set 0.payload file size.
func (tdfWriter *TDFWriter) SetPayloadSize(payloadSize int64) error {
	if payloadSize >= zip64MagicVal {
		tdfWriter.archiveWriter.EnableZip64()
	}
	tdfWriter.stats.PayloadSize = payloadSize

	return tdfWriter.archiveWriter.AddHeader(TDFPayloadFileName, payloadSize)
}

// AppendManifest Add the manifest to tdf archive.
func (tdfWriter *TDFWriter) AppendManifest(manifest string) error {
	manifestSize := int64(len(manifest))
	// FIXME: Manifests should never be bigger than maxManifestSize
	err := tdfWriter.archiveWriter.AddHeader(TDFManifestFileName, manifestSize)
	if err != nil {
		return err
	}
	tdfWriter.stats.ManifestSize = manifestSize

	return tdfWriter.archiveWriter.AddData([]byte(manifest))
}

func (tdfWriter TDFWriter) Stats() Stats {
	return tdfWriter.stats
}

// AppendPayload Add payload to sdk archive.
func (tdfWriter *TDFWriter) AppendPayload(data []byte) error {
	return tdfWriter.archiveWriter.AddData(data)
}

// Finish Finished adding all the files in zip archive.
func (tdfWriter *TDFWriter) Finish() (int64, error) {
	return tdfWriter.archiveWriter.Finish()
}
