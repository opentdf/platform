package cmd

import (
	_ "embed"
	"errors"
	"io"
	"testing"

	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

type mockReadSeeker struct {
	data []byte
	pos  int
}

func (m *mockReadSeeker) Read(p []byte) (int, error) {
	if m.pos >= len(m.data) {
		return 0, io.EOF
	}
	n := copy(p, m.data[m.pos:])
	m.pos += n
	return n, nil
}

func (m *mockReadSeeker) Seek(offset int64, whence int) (int64, error) {
	var newPos int
	switch whence {
	case io.SeekStart:
		newPos = int(offset)
	case io.SeekCurrent:
		newPos = m.pos + int(offset)
	case io.SeekEnd:
		newPos = len(m.data) + int(offset)
	default:
		return 0, errors.New("invalid whence")
	}
	if newPos < 0 || newPos > len(m.data) {
		return 0, errors.New("invalid seek position")
	}
	m.pos = newPos
	return int64(newPos), nil
}

//go:embed testdata/tdf-filewatcher-old.tdf
var sampleTDFFileWatcherOld []byte

//go:embed testdata/tdf-multikas.tdf
var sampleTDFMultiKas []byte

//go:embed testdata/tdf-valid.tdf
var sampleTDFValid []byte

func TestIsValid(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		isValidTdf bool
		tdfType    sdk.TdfType
	}{
		{
			name:       "Valid TDF3",
			data:       sampleTDFValid,
			isValidTdf: true,
			tdfType:    sdk.Standard,
		},
		{
			name:       "Invalid All",
			data:       []byte("invalid data"),
			isValidTdf: false,
			tdfType:    sdk.Invalid,
		},
		{
			name:       "Valid TDF3 (filewatcher)",
			data:       sampleTDFFileWatcherOld,
			isValidTdf: true,
			tdfType:    sdk.Standard,
		},
		{
			name:       "Valid TDF3 (multikas)",
			data:       sampleTDFMultiKas,
			isValidTdf: true,
			tdfType:    sdk.Standard,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := &mockReadSeeker{data: tt.data}
			cmd := &cobra.Command{}
			typeInfos := isValid(cmd, in)

			assert.Len(t, typeInfos, 2)
			assert.Equal(t, tt.isValidTdf, typeInfos[0].Valid)
			assert.Equal(t, tt.tdfType.String(), typeInfos[1].Type)
		})
	}
}
