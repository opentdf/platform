package tdf3_archiver

type TDFWriter struct {
	archiveWriter *ArchiveWriter
}

// CreateTDFWriter Create tdf writer instance
func CreateTDFWriter(outputProvider IOutputProvider) *TDFWriter {
	tdfWriter := TDFWriter{}
	tdfWriter.archiveWriter = CreateArchiveWriter(outputProvider)

	return &tdfWriter
}

// SetPayloadSize Set 0.payload file size
func (tdfWriter *TDFWriter) SetPayloadSize(payloadSize int64) error {

	if payloadSize >= zip64MagicVal {
		tdfWriter.archiveWriter.EnableZip64()
	}

	return tdfWriter.archiveWriter.SetFileSize(tdfPayloadFileName, payloadSize)
}

// AppendManifest Add the manifest to tdf3 archive
func (tdfWriter *TDFWriter) AppendManifest(manifest string) error {

	err := tdfWriter.archiveWriter.SetFileSize(tdfManifestFileName, int64(len(manifest)))
	if err != nil {
		return err
	}

	return tdfWriter.archiveWriter.AddDataToFile(tdfManifestFileName, []byte(manifest))
}

// AppendPayload Add payload to to tdf3 archive
func (tdfWriter *TDFWriter) AppendPayload(data []byte) error {
	return tdfWriter.archiveWriter.AddDataToFile(tdfPayloadFileName, data)
}

// Finish Completed adding all the files in zip archive
func (tdfWriter *TDFWriter) Finish() error {
	return tdfWriter.archiveWriter.Finish()
}
