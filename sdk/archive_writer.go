package sdk

import "github.com/opentdf/platform/sdk/internal/zipstream"

// ArchiveWriterFactory builds a zipstream.SegmentWriter for a new
// TDF. Tests inject in-memory fakes to observe segment layout
// without disk I/O.
type ArchiveWriterFactory func() zipstream.SegmentWriter

// DefaultArchiveWriterFactory returns a ZIP64-enabled segment writer
// sized for a single starting segment (grows as more segments
// arrive).
func DefaultArchiveWriterFactory() zipstream.SegmentWriter {
	return zipstream.NewSegmentTDFWriter(1, zipstream.WithZip64())
}
