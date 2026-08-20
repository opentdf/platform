package sdk

import "github.com/opentdf/platform/sdk/internal/zipstream"

// ArchiveWriterFactory builds a zipstream.SegmentWriter for a new
// TDF. Receives the writer's Clock so ZIP header timestamps stay
// injectable end-to-end. Tests inject in-memory fakes to observe
// segment layout without disk I/O.
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
