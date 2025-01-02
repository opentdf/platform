package sdk

import (
	"fmt"
	"os"
	"strings"
)

type Version struct {
	Major    int
	Minor    int
	Patch    int
	Preview  int
	Revision int
}

func ReadVersion() (*Version, error) {
	content, err := os.ReadFile("VERSION")
	if err != nil {
		return nil, fmt.Errorf("reading VERSION file: %w", err)
	}

	return ParseVersion(strings.TrimSpace(string(content)))
}

func ParseVersion(v string) (*Version, error) {
	const maxParts = 2
	var ver Version
	var preview, revision string

	parts := strings.SplitN(v, "+p", maxParts)
	mainVersion := parts[0]

	if len(parts) > 1 {
		if parts[1] == "" {
			return nil, fmt.Errorf("invalid preview format")
		}
		previewParts := strings.SplitN(parts[1], ".", maxParts)
		preview = previewParts[0]
		if len(previewParts) > 1 {
			if previewParts[1] == "" {
				return nil, fmt.Errorf("invalid revision format")
			}
			revision = previewParts[1]
		}
	}

	if _, err := fmt.Sscanf(mainVersion, "%d.%d.%d", &ver.Major, &ver.Minor, &ver.Patch); err != nil {
		return nil, fmt.Errorf("parsing version: %w", err)
	}

	if preview != "" {
		if _, err := fmt.Sscanf(preview, "%d", &ver.Preview); err != nil {
			return nil, fmt.Errorf("parsing preview version: %w", err)
		}
	}

	if revision != "" {
		if _, err := fmt.Sscanf(revision, "%d", &ver.Revision); err != nil {
			return nil, fmt.Errorf("parsing revision: %w", err)
		}
	}

	return &ver, nil
}

func (v *Version) String() string {
	base := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Preview > 0 {
		if v.Revision > 0 {
			return fmt.Sprintf("%s+p%d.%d", base, v.Preview, v.Revision)
		}
		return fmt.Sprintf("%s+p%d", base, v.Preview)
	}
	return base
}
