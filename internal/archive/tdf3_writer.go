package archive

import "io"

type TDFWriter struct {
	archiveWriter *Writer
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

// Close Completed adding all the files in zip archive.
func (tdfWriter *TDFWriter) Close() error {
	return tdfWriter.archiveWriter.Close()
}
