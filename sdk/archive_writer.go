package sdk

import "github.com/opentdf/platform/sdk/internal/zipstream"

// ArchiveWriterFactory builds a zipstream.SegmentWriter for a new
// TDF. Receives the writer's Clock so ZIP header timestamps stay
// injectable end-to-end.
//
// The seam is exported but implementable only from inside this module:
// zipstream.SegmentWriter lives under internal/, so no outside package
// can name the return type. Treat WithChunkedArchiveWriterFactory as
// an sdk-internal test hook rather than part of the supported API.
type ArchiveWriterFactory func(clock Clock) zipstream.SegmentWriter

// DefaultArchiveWriterFactory returns a ZIP64-enabled segment writer
// sized for a single starting segment (grows as more segments arrive),
// with its clock plumbed to the caller-supplied Clock.
func DefaultArchiveWriterFactory(clock Clock) zipstream.SegmentWriter {
	return zipstream.NewSegmentTDFWriter(1,
		zipstream.WithZip64(),
		zipstream.WithClock(clock.Now),
	)
}
