package tdf3_archiver

import (
	"fmt"
	"os"
	"path/filepath"
)

type FileOutputProvider struct {
	handle *os.File
	name   string
}

// CreateFileOutputProvider Create file output provider
func CreateFileOutputProvider(file string) (FileOutputProvider, error) {
	handle, err := os.Create(file)
	if err != nil {
		_ = handle.Close()
		return FileOutputProvider{}, err
	}

	fileOutputProvider := FileOutputProvider{}
	fileOutputProvider.handle = handle
	fileOutputProvider.name = filepath.Base(file)
	return fileOutputProvider, nil
}

// WriteBytes Write bytes in the buffer to the file
func (outputProvider FileOutputProvider) WriteBytes(buf []byte) error {
	count, err := outputProvider.handle.Write(buf)
	if err != nil {
		return err
	}

	if count != len(buf) {
		err = fmt.Errorf("FileOutputProvider: fail to write byte count:%d instead:%d", len(buf), count)
		return err
	}

	return nil
}

// DestroyFileOutputProvider Cleans resources
func (outputProvider FileOutputProvider) DestroyFileOutputProvider() {
	err := outputProvider.handle.Close()
	if err != nil {
		err = fmt.Errorf("FileOutputProvider: fail to close the file:%q error:%v", outputProvider.name, err)
		fmt.Println(err.Error())
	}
}
