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

func (m *mockReadSeeker) Read(p []byte) (n int, err error) {
	if m.pos >= len(m.data) {
		return 0, io.EOF
	}
	n = copy(p, m.data[m.pos:])
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

//go:embed testdata/nano-valid.ntdf
var sampleNanoValid []byte

//go:embed testdata/tdf-filewatcher-old.tdf
var sampleTDFFileWatcherOld []byte

//go:embed testdata/tdf-multikas.tdf
var sampleTDFMultiKas []byte

//go:embed testdata/tdf-valid.tdf
var sampleTDFValid []byte

func TestIsValid(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		isValidTdf  bool
		isValidNano bool
		tdfType     sdk.TdfType
	}{
		{
			name:        "Valid TDF3",
			data:        sampleTDFValid,
			isValidTdf:  true,
			isValidNano: false,
			tdfType:     sdk.Standard,
		},
		{
			name:        "Valid NanoTDF",
			data:        sampleNanoValid,
			isValidTdf:  false,
			isValidNano: true,
			tdfType:     sdk.Nano,
		},
		{
			name:        "Invalid All",
			data:        []byte("invalid data"),
			isValidTdf:  false,
			isValidNano: false,
			tdfType:     sdk.Invalid,
		},
		{
			name:        "Valid TDF3 (filewatcher)",
			data:        sampleTDFFileWatcherOld,
			isValidTdf:  true,
			isValidNano: false,
			tdfType:     sdk.Standard,
		},
		{
			name:        "Valid TDF3 (multikas)",
			data:        sampleTDFMultiKas,
			isValidTdf:  true,
			isValidNano: false,
			tdfType:     sdk.Standard,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := &mockReadSeeker{data: tt.data}
			cmd := &cobra.Command{}
			typeInfos := isValid(cmd, in)

			assert.Len(t, typeInfos, 3)
			assert.Equal(t, tt.isValidTdf, typeInfos[0].Valid)
			assert.Equal(t, tt.isValidNano, typeInfos[1].Valid)
			assert.Equal(t, tt.tdfType.String(), typeInfos[2].Type)
		})
	}
}
