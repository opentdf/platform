package artifact

import (
	"errors"
	"fmt"
	"io"

	"github.com/Masterminds/semver/v3"
	metadata "github.com/opentdf/platform/otdfctl/migrations/artifact/metadata"
	artifactv1 "github.com/opentdf/platform/otdfctl/migrations/artifact/v1"
)

const CurrentSchemaVersion = artifactv1.SchemaVersion

var (
	currentSchemaVersion = semver.MustParse(CurrentSchemaVersion)

	ErrInvalidSchemaVersion     = errors.New("invalid artifact schema version")
	ErrUnsupportedSchemaVersion = errors.New("unsupported artifact schema version")
	ErrNotImplemented           = errors.New("not implemented")
)

type ArtifactOpts struct {
	Version *semver.Version
	Writer  io.Writer
}

type Artifact interface {
	Build() error
	Commit() error
	Metadata() metadata.ArtifactMetadata
	Summary() ([]byte, error)
	Write() error
}

func New(opts ArtifactOpts) (Artifact, error) {
	version := opts.Version
	if version == nil {
		version = currentSchemaVersion
	}

	doc, err := newDocumentForVersion(version, opts.Writer)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

func newDocumentForVersion(version *semver.Version, writer io.Writer) (Artifact, error) {
	switch version.Major() {
	case 1:
		return artifactv1.New(writer)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedSchemaVersion, version.Original())
	}
}
