package sdk

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ============================================================================================================

// resourceLocator - structure to contain a protocol + body comprising an URL
type resourceLocator struct {
	protocol   urlProtocol
	lengthBody uint8 // TODO FIXME - redundant?
	body       string
}

// urlProtocol - shorthand for protocol prefix on fully qualified url
type urlProtocol uint8

const (
	kPrefixHTTPS      string      = "https://"
	kPrefixHTTP       string      = "http://"
	urlProtocolHTTP   urlProtocol = 0
	urlProtocolHTTPS  urlProtocol = 1
	urlProtocolShared urlProtocol = 255 // TODO - how is this handled/parsed/rendered?
)

func (rl *resourceLocator) getLength() uint64 {
	return uint64(1 /* protocol byte */ + 1 /* length byte */ + len(rl.body) /* length of string */)
}

// setUrl - Store a fully qualified protocol+body string into a resourceLocator as a protocol value and a body string
func (rl *resourceLocator) setUrl(url string) error {
	lowerUrl := strings.ToLower(url)
	if strings.HasPrefix(lowerUrl, kPrefixHTTPS) {
		urlBody := url[len(kPrefixHTTPS):]
		if len(urlBody) > 255 {
			return errors.New("URL too long")
		}
		rl.protocol = urlProtocolHTTPS
		rl.lengthBody = uint8(len(urlBody))
		rl.body = urlBody
		return nil
	}
	if strings.HasPrefix(lowerUrl, kPrefixHTTP) {
		urlBody := url[len(kPrefixHTTP):]
		if len(urlBody) > 255 {
			return errors.New("URL too long")
		}
		rl.protocol = urlProtocolHTTP
		rl.lengthBody = uint8(len(urlBody))
		rl.body = urlBody
		return nil
	}
	return errors.New("Unsupported protocol: " + url)
}

// getUrl - Retrieve a fully qualified protocol+body URL string from a resourceLocator struct
func (rl *resourceLocator) getUrl() (string, error) {
	if rl.protocol == urlProtocolHTTPS {
		return kPrefixHTTPS + rl.body, nil
	}
	if rl.protocol == urlProtocolHTTP {
		return kPrefixHTTP + rl.body, nil
	}
	return "", fmt.Errorf("Unsupported protocol: %d", rl.protocol)
}

// writeResourceLocator - writes the content of the resource locator to the supplied writer
func (rl *resourceLocator) writeResourceLocator(writer io.Writer) error {
	if err := binary.Write(writer, binary.BigEndian, byte(rl.protocol)); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, uint8(len(rl.body))); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, []byte(rl.body)); err != nil { // TODO - normalize to lowercase?
		return err
	}
	return nil
}

// readResourceLocator - read the encoded protocol and body string into a resourceLocator
func (rl *resourceLocator) readResourceLocator(reader io.Reader) error {
	if err := binary.Read(reader, binary.BigEndian, &rl.protocol); err != nil {
		return errors.Join(Error("Error reading resourceLocator protocol value"), err)
	}
	if (rl.protocol != urlProtocolHTTP) && (rl.protocol != urlProtocolHTTPS) { // TODO - support 'shared' protocol?
		return errors.New("Unsupported protocol: " + strconv.Itoa(int(rl.protocol)))
	}
	if err := binary.Read(reader, binary.BigEndian, &rl.lengthBody); err != nil {
		return errors.Join(Error("Error reading resourceLocator body length value"), err)
	}
	body := make([]byte, rl.lengthBody)
	if err := binary.Read(reader, binary.BigEndian, &body); err != nil {
		return errors.Join(Error("Error reading resourceLocator body value"), err)
	}
	rl.body = string(body) // TODO - normalize to lowercase?
	return nil
}
