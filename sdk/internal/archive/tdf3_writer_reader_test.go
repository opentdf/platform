package archive

import (
	"bytes"
	"os"
	"strconv"
	"testing"
)

type TDF3Entry struct {
	manifest    string
	payloadSize int64
	tdfSize     int64
}

var TDF3Tests = []TDF3Entry{ //nolint:gochecknoglobals // This global is used as test harness for other tests
	{
		manifest:    "some manifest",
		payloadSize: oneKB,
		tdfSize:     1291,
	},
	{
		manifest: `{
	"encryptionInformation": {
		"integrityInformation": {
			"encryptedSegmentSizeDefault": 1048604,
			"rootSignature": {
				"alg": "HS256",
				"sig": "ZjEwYWRjMzJkNzVhMmNkMzljYTU3ZDg3YTJjNjMyMGYwOTZkYjZhZDY4ZTE1Y2Y1MzRlNTdjNjBhNjdlNWUwMQ=="
			},
			"segmentHashAlg": "GMAC",
			"segmentSizeDefault": 1048576,
			"segments": [
				{
					"encryptedSegmentSize": 228,
					"hash": "YWRkNDhhZWM0Y2VhNmQwZjU5Y2ViOTc5MmFhYzdlOTI=",
					"segmentSize": 200
				}
			]
		},
		"keyAccess": [
			{
				"encryptedMetadata": "eyJjaXBoZXJ0ZXh0IjoidkwyOUVVb1IyOFpVNStiMzFDdE1iNFFVODF5dVhPTnM3SUtDYlZNcDloZkg3dCs2UFRPaG00VFAwbVRDc3R3UEFkeU1ucHltbk4rWWNON0hmbytDIiwiaXYiOiJ2TDI5RVVvUjI4WlU1K2IzIn0=",
				"policyBinding": "Zjk1Mjg2ZDljMzYwNGE5ZmU3YWE2M2UzOWRmMjA5MGU2OTJkYTZiYjExNjFkZmZjNTI2N2JkMWY5M2Y3MzIzZQ==",
				"protocol": "kas",
				"type": "wrapped",
				"url": "http://localhost:65432/api/kas",
				"wrappedKey": "ARu5wnJPNDaivQymXKOogyC2n11QP4Jf8ZYtrAcYQnUmE9hsjQD2R+48js5T1LkNLp5TzaRREF5sSk5/dhlBge/YXVcT42d5lNp0SecAF68dsso/aXq+G2sRJFVWdYKAtc32mr8KJiPisHtPlPFPM7u37lU0YX93lsqIxiUPn6qkxkD4cEozvA9UgB8YZ8alJtNACnpbOUebJeRLkHbxXM7DzW4gur/lu88lRUtCdaHNBeSOTCgWi2oqTU70asyoFQVVD7R80xKblam5k/B3PKhCkerZkDwyy5D4eODbbqKpGfbluW6NWEM+HtYnJFa+2kJB51yqylsbUnfpWEBQDA=="
			}
		],
		"method": {
			"algorithm": "AES-256-GCM",
			"isStreamable": true,
			"iv": "vL29EUoR28ZU5+b3"
		},
		"policy": "eyJib2R5Ijp7ImRhdGFBdHRyaWJ1dGVzIjpbXSwiZGlzc2VtIjpbXX0sInV1aWQiOiJlMDk0NmVhNC1mZDMzLTQ3ODktODM3Ny1hMzhiMjNhOTc1MmIifQ==",
		"type": "split"
	},
	"payload": {
		"isEncrypted": true,
		"mimeType": "application/octet-stream",
		"protocol": "zip",
		"type": "reference",
		"url": "0.payload"
	}
}`,
		payloadSize: 10 * oneMB,
		tdfSize:     10487693,
	},
	{
		manifest: `{
	"encryptionInformation": {
		"integrityInformation": {
			"encryptedSegmentSizeDefault": 1048604,
			"rootSignature": {
				"alg": "HS256",
				"sig": "ZjEwYWRjMzJkNzVhMmNkMzljYTU3ZDg3YTJjNjMyMGYwOTZkYjZhZDY4ZTE1Y2Y1MzRlNTdjNjBhNjdlNWUwMQ=="
			},
			"segmentHashAlg": "GMAC",
			"segmentSizeDefault": 1048576,
			"segments": [
				{
					"encryptedSegmentSize": 228,
					"hash": "YWRkNDhhZWM0Y2VhNmQwZjU5Y2ViOTc5MmFhYzdlOTI=",
					"segmentSize": 200
				}
			]
		},
		"keyAccess": [
			{
				"encryptedMetadata": "eyJjaXBoZXJ0ZXh0IjoidkwyOUVVb1IyOFpVNStiMzFDdE1iNFFVODF5dVhPTnM3SUtDYlZNcDloZkg3dCs2UFRPaG00VFAwbVRDc3R3UEFkeU1ucHltbk4rWWNON0hmbytDIiwiaXYiOiJ2TDI5RVVvUjI4WlU1K2IzIn0=",
				"policyBinding": "Zjk1Mjg2ZDljMzYwNGE5ZmU3YWE2M2UzOWRmMjA5MGU2OTJkYTZiYjExNjFkZmZjNTI2N2JkMWY5M2Y3MzIzZQ==",
				"protocol": "kas",
				"type": "wrapped",
				"url": "http://localhost:65432/api/kas",
				"wrappedKey": "ARu5wnJPNDaivQymXKOogyC2n11QP4Jf8ZYtrAcYQnUmE9hsjQD2R+48js5T1LkNLp5TzaRREF5sSk5/dhlBge/YXVcT42d5lNp0SecAF68dsso/aXq+G2sRJFVWdYKAtc32mr8KJiPisHtPlPFPM7u37lU0YX93lsqIxiUPn6qkxkD4cEozvA9UgB8YZ8alJtNACnpbOUebJeRLkHbxXM7DzW4gur/lu88lRUtCdaHNBeSOTCgWi2oqTU70asyoFQVVD7R80xKblam5k/B3PKhCkerZkDwyy5D4eODbbqKpGfbluW6NWEM+HtYnJFa+2kJB51yqylsbUnfpWEBQDA=="
			}
		],
		"method": {
			"algorithm": "AES-256-GCM",
			"isStreamable": true,
			"iv": "vL29EUoR28ZU5+b3"
		},
		"policy": "eyJib2R5Ijp7ImRhdGFBdHRyaWJ1dGVzIjpbXSwiZGlzc2VtIjpbXX0sInV1aWQiOiJlMDk0NmVhNC1mZDMzLTQ3ODktODM3Ny1hMzhiMjNhOTc1MmIifQ==",
		"type": "split"
	},
	"payload": {
		"isEncrypted": true,
		"mimeType": "application/octet-stream",
		"protocol": "zip",
		"type": "reference",
		"url": "0.payload"
	}
}`,
		payloadSize: 3 * oneGB,
		tdfSize:     3145729933,
	},
	{
		manifest: `{
	"encryptionInformation": {
		"integrityInformation": {
			"encryptedSegmentSizeDefault": 1048604,
			"rootSignature": {
				"alg": "HS256",
				"sig": "ZjEwYWRjMzJkNzVhMmNkMzljYTU3ZDg3YTJjNjMyMGYwOTZkYjZhZDY4ZTE1Y2Y1MzRlNTdjNjBhNjdlNWUwMQ=="
			},
			"segmentHashAlg": "GMAC",
			"segmentSizeDefault": 1048576,
			"segments": [
				{
					"encryptedSegmentSize": 228,
					"hash": "YWRkNDhhZWM0Y2VhNmQwZjU5Y2ViOTc5MmFhYzdlOTI=",
					"segmentSize": 200
				}
			]
		},
		"keyAccess": [
			{
				"encryptedMetadata": "eyJjaXBoZXJ0ZXh0IjoidkwyOUVVb1IyOFpVNStiMzFDdE1iNFFVODF5dVhPTnM3SUtDYlZNcDloZkg3dCs2UFRPaG00VFAwbVRDc3R3UEFkeU1ucHltbk4rWWNON0hmbytDIiwiaXYiOiJ2TDI5RVVvUjI4WlU1K2IzIn0=",
				"policyBinding": "Zjk1Mjg2ZDljMzYwNGE5ZmU3YWE2M2UzOWRmMjA5MGU2OTJkYTZiYjExNjFkZmZjNTI2N2JkMWY5M2Y3MzIzZQ==",
				"protocol": "kas",
				"type": "wrapped",
				"url": "http://localhost:65432/api/kas",
				"wrappedKey": "ARu5wnJPNDaivQymXKOogyC2n11QP4Jf8ZYtrAcYQnUmE9hsjQD2R+48js5T1LkNLp5TzaRREF5sSk5/dhlBge/YXVcT42d5lNp0SecAF68dsso/aXq+G2sRJFVWdYKAtc32mr8KJiPisHtPlPFPM7u37lU0YX93lsqIxiUPn6qkxkD4cEozvA9UgB8YZ8alJtNACnpbOUebJeRLkHbxXM7DzW4gur/lu88lRUtCdaHNBeSOTCgWi2oqTU70asyoFQVVD7R80xKblam5k/B3PKhCkerZkDwyy5D4eODbbqKpGfbluW6NWEM+HtYnJFa+2kJB51yqylsbUnfpWEBQDA=="
			}
		],
		"method": {
			"algorithm": "AES-256-GCM",
			"isStreamable": true,
			"iv": "vL29EUoR28ZU5+b3"
		},
		"policy": "eyJib2R5Ijp7ImRhdGFBdHRyaWJ1dGVzIjpbXSwiZGlzc2VtIjpbXX0sInV1aWQiOiJlMDk0NmVhNC1mZDMzLTQ3ODktODM3Ny1hMzhiMjNhOTc1MmIifQ==",
		"type": "split"
	},
	"payload": {
		"isEncrypted": true,
		"mimeType": "application/octet-stream",
		"protocol": "zip",
		"type": "reference",
		"url": "0.payload"
	}
}`,
		payloadSize: 10 * oneGB,
		tdfSize:     10485762121,
	},
}

func TestTDF3Writer_and_Reader(t *testing.T) { // Create tdf files
	writeTDFs(t)

	// Read the tdf files
	// NOTE: It will also deletes after reading them
	readTDFs(t)
}

func writeTDFs(t *testing.T) {
	for index := 0; index < len(writeBuffer); index++ {
		writeBuffer[index] = 0xFF
	}

	for index, tdf3Entry := range TDF3Tests { // tdf3 file name as index
		tdf3Name := strconv.Itoa(index) + ".zip"

		writer, err := os.Create(tdf3Name)
		if err != nil {
			t.Fatalf("Fail to open archive file: %v", err)
		}

		defer func(outputProvider *os.File) {
			err := outputProvider.Close()
			if err != nil {
				t.Fatalf("Fail to close archive file: %v", err)
			}
		}(writer)

		tdf3Writer := NewTDFWriter(writer)

		// write payload
		totalBytes := tdf3Entry.payloadSize
		err = tdf3Writer.SetPayloadSize(totalBytes)
		if err != nil {
			t.Fatalf("Fail to set payload size: %v", err)
		}

		var bytesToWrite int64
		for totalBytes > 0 {
			if totalBytes >= stepSize {
				totalBytes -= stepSize
				bytesToWrite = stepSize
			} else {
				bytesToWrite = totalBytes
				totalBytes = 0
			}

			err = tdf3Writer.AppendPayload(writeBuffer[:bytesToWrite])
			if err != nil {
				t.Fatalf("Fail to add payload to tdf3 writer: %v", err)
			}
		}

		// write manifest
		err = tdf3Writer.AppendManifest(tdf3Entry.manifest)
		if err != nil {
			t.Fatalf("Fail to add payload to tdf3 writer: %v", err)
		}

		tdfSize, err := tdf3Writer.Finish()
		if err != nil {
			t.Fatalf("Fail to close tdf3 writer: %v", err)
		}

		if tdfSize != tdf3Entry.tdfSize {
			t.Errorf("tdf size test failed expected %v, got %v", tdfSize, tdf3Entry.tdfSize)
		}
	}
}

func readTDFs(t *testing.T) {
	for index, tdf3Entry := range TDF3Tests {
		// tdf3 file name as index
		tdf3Name := strconv.Itoa(index) + ".zip"

		inputProvider, err := os.Open(tdf3Name)
		if err != nil {
			t.Fatalf("Fail to open archive file:%s %v", tdf3Name, err)
		}

		defer func(inputProvider *os.File) {
			err := inputProvider.Close()
			if err != nil {
				t.Fatalf("Fail to close archive file:%s %v", tdf3Name, err)
			}
		}(inputProvider)

		tdf3Reader, err := NewTDFReader(inputProvider)
		if err != nil {
			t.Fatalf("Fail to create archive %v", err)
		}

		// read manifest
		manifest, err := tdf3Reader.Manifest()
		if err != nil {
			t.Fatalf("Fail to read manifest from tdf3 reader %v", err)
		}

		if manifest != tdf3Entry.manifest {
			t.Fatalf("Fail to compate manifest contents")
		}

		// read the payload
		readIndex := int64(0)
		var bytesToRead int64
		totalBytes := tdf3Entry.payloadSize
		for totalBytes > 0 {
			if totalBytes >= stepSize {
				totalBytes -= stepSize
				bytesToRead = stepSize
			} else {
				bytesToRead = totalBytes
				totalBytes = 0
			}

			buf, err := tdf3Reader.ReadPayload(readIndex, bytesToRead)
			if err != nil {
				t.Fatalf("Fail to read from tdf3 reader: %v", err)
			}

			readIndex += bytesToRead

			if !bytes.Equal(buf, writeBuffer[:bytesToRead]) {
				t.Fatalf("Fail to compare zip contents")
			}
		}

		err = os.Remove(tdf3Name)
		if err != nil {
			t.Fatalf("Fail to remove zip file :%s archive %v", tdf3Name, err)
		}
	}
}
