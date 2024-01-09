package tdf3_archiver

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"strconv"
	"testing"
)

func TestCreateArchiveReader(t *testing.T) {

	// use native library("archive/zip") to create zip files
	nativeZipFiles(t)

	// use custom implementation to unzip
	customUnzip(t)
}

func nativeZipFiles(t *testing.T) {

	for index := 0; index < len(writeBuffer); index++ {
		writeBuffer[index] = 0xFF
	}

	// create the zip files using naive library
	for index, zipEntries := range ArchiveTests {

		// zip file name as index
		zipFileName := strconv.Itoa(index) + ".zip"

		// Open the zip file
		archive, err := os.Create(zipFileName)
		if err != nil {
			t.Fatalf("Fail to create to archive: %v", err)
		}
		defer func(archive *os.File) {
			err := archive.Close()
			if err != nil {
				t.Fatalf("Fail to close the closer: %v", err)
			}
		}(archive)

		// Create a new zip writer.
		writer := zip.NewWriter(archive)
		defer func(writer *zip.Writer) {
			err := writer.Close()
			if err != nil {
				t.Fatalf("Fail to close the writer: %v", err)
			}
		}(writer)

		// Iterate over the entries to create files
		for _, entry := range zipEntries.files {

			input, err := writer.CreateHeader(&zip.FileHeader{
				Name:   entry.filename,
				Method: zip.Store,
			})
			if err != nil {
				t.Fatalf("Fail to create to archive entry:%s %v", entry.filename, err)
			}

			totalBytes := entry.size
			for totalBytes > 0 {

				bytesToWrite := int64(0)
				if totalBytes >= stepSize {
					totalBytes -= stepSize
					bytesToWrite = stepSize
				} else {
					bytesToWrite = totalBytes
					totalBytes = 0
				}

				reader := bytes.NewReader(writeBuffer[:bytesToWrite])
				_, err = io.Copy(input, reader)
				if err != nil {
					t.Fatalf("Fail to write to archive file:%s : %v", entry.filename, err)
				}

				//_, err := input.Write(writeBuffer[:bytesToWrite])
				//if err != nil {
				//	t.Fatalf("Fail to write to archive file:%s : %v", entry.filename, err)
				//}
			}

		}
	}
}

func customUnzip(t *testing.T) {
	// unzip the zip files using the custom implementation
	// test the zip file you created
	for index, fileEntries := range ArchiveTests {

		// zip file name as index
		zipFileName := strconv.Itoa(index) + ".zip"

		inputProvider, err := CreateFileInputProvider(zipFileName)
		if err != nil {
			t.Fatalf("Fail to create input provider for file:%s %v", zipFileName, err)
		}

		defer inputProvider.Close()

		archiver, err := CreateArchiveReader(inputProvider)
		if err != nil {
			t.Fatalf("Fail to create archiver %v", err)
		}

		// Iterate over the files in the zip file
		for _, zipEntry := range fileEntries.files {

			totalBytes, err := archiver.ReadFileSize(zipEntry.filename)
			if err != nil {
				t.Fatalf("Fail to read the file:%s size archiver", zipEntry.filename)
			}

			fileIndex := int64(0)
			bytesToRead := int64(0)
			for totalBytes > 0 {
				if totalBytes >= stepSize {
					totalBytes -= stepSize
					bytesToRead = stepSize
				} else {
					bytesToRead = totalBytes
					totalBytes = 0
				}

				buf, err := archiver.ReadFileData(zipEntry.filename, fileIndex, bytesToRead)
				if err != nil {
					t.Fatalf("Fail to read from archive file:%s : %v", zipEntry.filename, err)
				}

				fileIndex += bytesToRead

				if bytes.Compare(buf, writeBuffer[:bytesToRead]) != 0 {
					t.Fatalf("Fail to compare zip contents")
				}
			}
		}

		err = os.Remove(zipFileName)
		if err != nil {
			t.Fatalf("Fail to remove zip file :%s archive %v", zipFileName, err)
		}
	}
}
