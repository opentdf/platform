package archive

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"log"
	"strings"
)

const (
	ErrCopy         = Error("archive error copy")
	ErrZipFormat    = Error("archive zip error")
	ErrManifestRead = Error("archive manifest error")
)

// TODO add validate function to be used by CLI and web
// find file
// check zip
// check contents
// check payload is correct
// check integrity versus manifest

// Valid reports errors if r is an invalid TDF3 archive.
func Valid(r io.Reader) error {
	buff := bytes.NewBuffer([]byte{})
	size, err := io.Copy(buff, r)
	if err != nil {
		return errors.Join(ErrCopy, err)
	}
	reader := bytes.NewReader(buff.Bytes())
	zipReader, err := zip.NewReader(reader, size)
	if err != nil {
		return errors.Join(ErrZipFormat, err)
	}
	for _, f := range zipReader.File {
		if strings.Contains(f.Name, "manifest") {
			rc, err := f.Open()
			if err != nil {
				return errors.Join(ErrManifestRead, err)
			}
			manifest, err := io.ReadAll(rc)
			if err != nil {
				return errors.Join(ErrManifestRead, err)
			}
			_ = rc.Close()
			log.Println(manifest)
		}
	}
	return nil
}

type Error string

func (e Error) Error() string {
	return string(e)
}
