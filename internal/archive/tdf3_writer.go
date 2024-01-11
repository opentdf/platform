package archive

import "io"

type TDFWriter struct {
	archiveWriter *Writer
}

// CreateTDFWriter Create tdf writer instance.
func CreateTDFWriter(writer io.Writer) *TDFWriter {
	tdfWriter := TDFWriter{}
	tdfWriter.archiveWriter = CreateWriter(writer)

	return &tdfWriter
}

// SetPayloadSize Set 0.payload file size.
func (tdfWriter *TDFWriter) SetPayloadSize(payloadSize int64) error {
	if payloadSize >= zip64MagicVal {
		tdfWriter.archiveWriter.EnableZip64()
	}

	return tdfWriter.archiveWriter.AddHeader(tdfPayloadFileName, payloadSize)
}

// AppendManifest Add the manifest to tdf3 archive.
func (tdfWriter *TDFWriter) AppendManifest(manifest string) error {
	err := tdfWriter.archiveWriter.AddHeader(tdfManifestFileName, int64(len(manifest)))
	if err != nil {
		return err
	}

	return tdfWriter.archiveWriter.AddData([]byte(manifest))
}

// AppendPayload Add payload to tdf3 archive.
func (tdfWriter *TDFWriter) AppendPayload(data []byte) error {
	return tdfWriter.archiveWriter.AddData(data)
}

// Finish Completed adding all the files in zip archive.
func (tdfWriter *TDFWriter) Finish() error {
	return tdfWriter.archiveWriter.Finish()
}
