package archive

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"strconv"
	"testing"
)

const (
	oneKB     = 1024
	tenKB     = 10 * oneKB
	oneMB     = 1024 * 1024
	hundredMB = 100 * oneMB
	oneGB     = 10 * hundredMB
	tenGB     = 10 * oneGB
)

type ZipEntryInfo struct {
	filename string
	size     int64
}

var ArchiveTests = []struct { //nolint:gochecknoglobals // This global is used as test harness for other tests
	files       []ZipEntryInfo
	archiveSize int64
}{
	{
		[]ZipEntryInfo{
			{
				"1.txt",
				10,
			},
			{
				"2.txt",
				10,
			},
			{
				"3.txt",
				10,
			},
		},
		358,
	},
	{
		[]ZipEntryInfo{
			{
				"1.txt",
				oneKB,
			},
			{
				"2.txt",
				oneKB,
			},
			{
				"3.txt",
				oneKB,
			},
			{
				"4.txt",
				oneKB,
			},
			{
				"5.txt",
				oneKB,
			},
			{
				"6.txt",
				oneKB,
			},
		},
		6778,
	},
	{
		[]ZipEntryInfo{
			{
				"1.txt",
				hundredMB,
			},
			{
				"2.txt",
				hundredMB,
			},
			{
				"3.txt",
				hundredMB,
			},
			{
				"4.txt",
				hundredMB,
			},
			{
				"5.txt",
				hundredMB + oneMB + tenKB,
			},
			{
				".txt",
				oneMB + oneKB,
			},
		},
		526397048,
	},
}

// create a buffer of 2mb and fill it with 0xFF, and
// it used to fill with the contents of the files
var (
	stepSize    int64 = 2 * oneMB              //nolint:gochecknoglobals // This global is used in other tests
	writeBuffer       = make([]byte, stepSize) //nolint:gochecknoglobals // This is used as reuse buffer
)

func TestCreateArchiveReader(t *testing.T) { // use native library("archive/zip") to create zip files
	nativeZipFiles(t)

	// use custom implementation to unzip
	customUnzip(t)
}

func nativeZipFiles(t *testing.T) {
	for index := 0; index < len(writeBuffer); index++ {
		writeBuffer[index] = 0xFF
	}

	// create the zip files using naive library
	for index, zipEntries := range ArchiveTests { // zip file name as index
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
			var bytesToWrite int64
			for totalBytes > 0 {
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

		readSeeker, err := os.Open(zipFileName)
		if err != nil {
			t.Fatalf("Fail to open archive file:%s %v", zipFileName, err)
		}

		defer func(readSeeker *os.File) {
			err := readSeeker.Close()
			if err != nil {
				t.Fatalf("Fail to close archive file:%v", err)
			}
		}(readSeeker)

		reader, err := NewReader(readSeeker)
		if err != nil {
			t.Fatalf("Fail to create archive %v", err)
		}

		// Iterate over the files in the zip file
		for _, zipEntry := range fileEntries.files {
			totalBytes, err := reader.ReadFileSize(zipEntry.filename)
			if err != nil {
				t.Fatalf("Fail to read the file:%s size archive", zipEntry.filename)
			}

			fileIndex := int64(0)
			var bytesToRead int64
			for totalBytes > 0 {
				if totalBytes >= stepSize {
					totalBytes -= stepSize
					bytesToRead = stepSize
				} else {
					bytesToRead = totalBytes
					totalBytes = 0
				}

				buf, err := reader.ReadFileData(zipEntry.filename, fileIndex, bytesToRead)
				if err != nil {
					t.Fatalf("Fail to read from archive file:%s : %v", zipEntry.filename, err)
				}

				fileIndex += bytesToRead

				if !bytes.Equal(buf, writeBuffer[:bytesToRead]) {
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
