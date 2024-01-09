package tdf3_archiver

import (
	"fmt"
	"os"
	"path/filepath"
)

type FileInputProvider struct {
	handle *os.File
	name   string
	size   int64
}

// CreateFileInputProvider Create file input provider
func CreateFileInputProvider(file string) (FileInputProvider, error) {
	handle, err := os.Open(file)
	if err != nil {
		_ = handle.Close()
		return FileInputProvider{}, err
	}

	fileInfo, err := handle.Stat()
	if err != nil {
		_ = handle.Close()
		return FileInputProvider{}, err
	}

	fileInputProvider := FileInputProvider{}
	fileInputProvider.name = filepath.Base(file)
	fileInputProvider.size = fileInfo.Size()
	fileInputProvider.handle = handle
	return fileInputProvider, nil
}

// ReadBytes Read bytes reads up to size from input providers
// and return the buffer with the read bytes.
func (inputProvider FileInputProvider) ReadBytes(index, size int64) ([]byte, error) {

	_, err := inputProvider.handle.Seek(index, 0)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, size)
	_, err = inputProvider.handle.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

// GetSize Return the total size of the input provider
func (inputProvider FileInputProvider) GetSize() int64 {
	return inputProvider.size
}

// Close Cleans resources
func (inputProvider FileInputProvider) Close() {
	err := inputProvider.handle.Close()
	if err != nil {
		err = fmt.Errorf("FileInputProvider: fail to close the file:%q error:%v", inputProvider.name, err)
		fmt.Println(err.Error())
	}
}
