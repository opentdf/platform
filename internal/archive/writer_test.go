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

	{
		[]ZipEntryInfo{
			{
				"1.txt",
				oneGB,
			},
			{
				"2.txt",
				oneGB,
			},
			{
				"3.txt",
				tenGB,
			},
		},
		12582912572,
	},
}

// create a buffer of 2mb and fill it with 0xFF, and
// it used to fill with the contents of the files
var stepSize int64 = 2 * oneMB           //nolint:gochecknoglobals // This global is used in other tests
var writeBuffer = make([]byte, stepSize) //nolint:gochecknoglobalsas // This is used as reuse buffer
// in other tests

func TestCreateArchiveWriter(t *testing.T) { // use custom implementation of zip
	customZip(t)

	// use native library("archive/zip") to unzip files
	nativeUnzips(t)
}

func customZip(t *testing.T) {

	for index := 0; index < len(writeBuffer); index++ {
		writeBuffer[index] = 0xFF
	}

	// create test zip files
	for index, test := range ArchiveTests { // zip file name as index
		zipFileName := strconv.Itoa(index) + ".zip"
		writer, err := os.Create(zipFileName)
		if err != nil {
			t.Fatalf("Fail to open archive file: %v", err)
		}

		defer func(outputProvider *os.File) {
			err := outputProvider.Close()
			if err != nil {
				t.Fatalf("Fail to close archive file: %v", err)
			}
		}(writer)

		archiveWriter := NewWriter(writer)

		// calculate total size of the zip file contents
		var totalContentSize int64
		for i := 0; i < len(test.files); i++ {
			fileInfo := test.files[i]
			totalContentSize += fileInfo.size
		}

		if totalContentSize >= zip64MagicVal {
			archiveWriter.EnableZip64()
		}

		// add data
		for i := 0; i < len(test.files); i++ {
			fileInfo := test.files[i]

			err = archiveWriter.AddHeader(fileInfo.filename, fileInfo.size)
			if err != nil {
				t.Fatalf("Fail to set the size of file in archive: %v", err)
			}

			totalBytes := fileInfo.size
			var bytesToWrite int64
			for totalBytes > 0 {
				if totalBytes >= stepSize {
					totalBytes -= stepSize
					bytesToWrite = stepSize
				} else {
					bytesToWrite = totalBytes
					totalBytes = 0
				}

				err = archiveWriter.AddData(writeBuffer[:bytesToWrite])
				if err != nil {
					t.Fatalf("Fail to write to archive: %v", err)
				}
			}
		}

		archiveSize, err := archiveWriter.Finish()
		if err != nil {
			t.Fatalf("Fail to close to archive: %v", err)
		}

		if archiveSize != test.archiveSize {
			t.Errorf("archive size test failed expected %v, got %v", archiveSize, test.archiveSize)
		}
	}
}

func nativeUnzips(t *testing.T) {

	// Read buffer
	readSize := int64(2 * oneMB)
	readBuffer := make([]byte, readSize)

	// test the zip file you created
	for index := range ArchiveTests {
		// zip file name as index
		zipFileName := strconv.Itoa(index) + ".zip"

		// Open the zip file
		r, err := zip.OpenReader(zipFileName)
		if err != nil {
			t.Fatalf("Fail to open to archive: %v", err)
		}
		defer func(r *zip.ReadCloser) {
			err := r.Close()
			if err != nil {
				t.Fatalf("Fail to close to archive: %v", err)
			}
		}(r)

		// Iterate over the files in the zip file
		for _, f := range r.File {
			// open the file
			fc, err := f.Open()
			if err != nil {
				t.Fatalf("Fail to open zip:%s archive %v", zipFileName, err)
			}
			defer func(fc io.ReadCloser) {
				err := fc.Close()
				if err != nil {
					t.Fatalf("Fail to close file %v", err)
				}
			}(fc)

			fileInfo := f.FileInfo()
			totalBytes := fileInfo.Size()
			for totalBytes > 0 {
				var bytesToRead int64
				if totalBytes >= stepSize {
					totalBytes -= stepSize
					bytesToRead = stepSize
				} else {
					bytesToRead = totalBytes
					totalBytes = 0
				}

				if _, err = fc.Read(readBuffer[:bytesToRead]); err != nil {
					t.Fatalf("Fail to read from archive file:%s : %v", fileInfo.Name(), err)
				}

				if !bytes.Equal(readBuffer[:bytesToRead], writeBuffer[:bytesToRead]) {
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
