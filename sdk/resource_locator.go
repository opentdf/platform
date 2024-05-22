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
// Support for serializing/deserializing URLS for nano usage
//
// If an URL is specified as "https://some.site.com/endpoint"
// the storage format for this is to strip off the leading "https://" prefix and encode as 0 (or 1 for http)
// followed by the run-length-prefixed body value
// ============================================================================================================

// ResourceLocator - structure to contain a protocol + body comprising an URL
type ResourceLocator struct {
	protocol urlProtocol // See urlProtocol values below
	body     string      // Body of url
}

// urlProtocol - shorthand for protocol prefix on fully qualified url
type urlProtocol uint8

const (
	kMaxBodyLen      int         = 255
	kPrefixHTTPS     string      = "https://"
	kPrefixHTTP      string      = "http://"
	urlProtocolHTTP  urlProtocol = 0
	urlProtocolHTTPS urlProtocol = 1
	// urlProtocolShared urlProtocol = 255 // TODO - how is this handled/parsed/rendered?
)

func NewResourceLocator(url string) (*ResourceLocator, error) {
	rl := &ResourceLocator{}

	err := rl.setURL(url)
	if err != nil {
		return nil, err
	}

	return rl, err
}

func NewResourceLocatorFromReader(reader io.Reader) (*ResourceLocator, error) {
	rl := &ResourceLocator{}
	oneByte := make([]byte, 1)

	_, err := reader.Read(oneByte)
	if err != nil {
		return rl, err
	}
	rl.protocol = urlProtocol(oneByte[0])

	_, err = reader.Read(oneByte)
	if err != nil {
		return rl, err
	}

	l := oneByte[0]
	body := make([]byte, l)
	_, err = reader.Read(body)
	if err != nil {
		return rl, err
	}
	rl.body = string(body)

	return rl, err
}

// getLength - return the serialized length (in bytes) of this object
func (rl ResourceLocator) getLength() uint16 {
	return uint16(1 /* protocol byte */ + 1 /* length byte */ + len(rl.body))
}

// setURL - Store a fully qualified protocol+body string into a ResourceLocator as a protocol value and a body string
func (rl *ResourceLocator) setURL(url string) error {
	lowerURL := strings.ToLower(url)
	if strings.HasPrefix(lowerURL, kPrefixHTTPS) {
		urlBody := url[len(kPrefixHTTPS):]
		if len(urlBody) > kMaxBodyLen {
			return errors.New("URL too long")
		}
		rl.protocol = urlProtocolHTTPS
		rl.body = urlBody
		return nil
	}
	if strings.HasPrefix(lowerURL, kPrefixHTTP) {
		urlBody := url[len(kPrefixHTTP):]
		if len(urlBody) > kMaxBodyLen {
			return errors.New("URL too long")
		}
		rl.protocol = urlProtocolHTTP
		rl.body = urlBody
		return nil
	}
	return errors.New("unsupported protocol: " + url)
}

// getURL - Retrieve a fully qualified protocol+body URL string from a ResourceLocator struct
func (rl ResourceLocator) getURL() (string, error) {
	if rl.protocol == urlProtocolHTTPS {
		return kPrefixHTTPS + rl.body, nil
	}
	if rl.protocol == urlProtocolHTTP {
		return kPrefixHTTP + rl.body, nil
	}
	return "", fmt.Errorf("unsupported protocol: %d", rl.protocol)
}

// writeResourceLocator - writes the content of the resource locator to the supplied writer
func (rl ResourceLocator) writeResourceLocator(writer io.Writer) error {
	if _, err := writer.Write([]byte{byte(rl.protocol)}); err != nil {
		return err
	}

	if _, err := writer.Write([]byte{byte(len(rl.body))}); err != nil {
		return err
	}

	if _, err := writer.Write([]byte(rl.body)); err != nil {
		return err
	}

	return nil
}

// readResourceLocator - read the encoded protocol and body string into a ResourceLocator
func (rl *ResourceLocator) readResourceLocator(reader io.Reader) error {
	if err := binary.Read(reader, binary.BigEndian, &rl.protocol); err != nil {
		return errors.Join(Error("Error reading ResourceLocator protocol value"), err)
	}
	if (rl.protocol != urlProtocolHTTP) && (rl.protocol != urlProtocolHTTPS) { // TODO - support 'shared' protocol?
		return errors.New("Unsupported protocol: " + strconv.Itoa(int(rl.protocol)))
	}
	var lengthBody byte
	if err := binary.Read(reader, binary.BigEndian, &lengthBody); err != nil {
		return errors.Join(Error("Error reading ResourceLocator body length value"), err)
	}
	body := make([]byte, lengthBody)
	if err := binary.Read(reader, binary.BigEndian, &body); err != nil {
		return errors.Join(Error("Error reading ResourceLocator body value"), err)
	}
	rl.body = string(body) // TODO - normalize to lowercase?
	return nil
}
