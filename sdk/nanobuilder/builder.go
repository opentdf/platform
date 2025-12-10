package nanobuilder

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
)

const MaxTDFSize = ((16 * 1024 * 1024) - 3 - 32)

// ============================================================================================================
// Factory: CreateNanoTDF
// ============================================================================================================

// NewNanoTDFCreator returns a function that orchestrates TDF creation.
func NewNanoTDFCreator[C HeaderConfig](
	resolver KeyResolver[C],
	headerWriter HeaderWriter[C],
	encryptor Encryptor,
) func(io.Writer, io.Reader, C) (uint32, error) {

	return func(writer io.Writer, reader io.Reader, config C) (uint32, error) {
		if writer == nil {
			return 0, errors.New("writer is nil")
		}
		if reader == nil {
			return 0, errors.New("reader is nil")
		}

		// 1. Read Payload
		buf := bytes.Buffer{}
		size, err := buf.ReadFrom(reader)
		if err != nil {
			return 0, err
		}
		if size > MaxTDFSize {
			return 0, errors.New("exceeds max size for nano tdf")
		}

		// 2. Resolve Keys (Mutates config)
		if err := resolver.Resolve(context.Background(), &config); err != nil {
			return 0, fmt.Errorf("key resolution failed: %w", err)
		}

		// 3. Write Header
		symKey, totalSize, iteration, err := headerWriter.Write(writer, config)
		if err != nil {
			return 0, fmt.Errorf("write header failed: %w", err)
		}

		slog.Debug("checkpoint CreateNanoTDF", "header", totalSize)

		// 4. Prepare Encryption
		iv, err := encryptor.GenerateIV(iteration)
		if err != nil {
			return 0, fmt.Errorf("iv generation failed: %w", err)
		}

		tagSize, err := encryptor.GetTagSize(int(config.GetSignatureConfig().Cipher))
		if err != nil {
			return 0, fmt.Errorf("tag size resolution failed: %w", err)
		}

		// 5. Encrypt
		cipherData, err := encryptor.Encrypt(buf.Bytes(), symKey, iv, tagSize)
		if err != nil {
			return 0, fmt.Errorf("encryption failed: %w", err)
		}

		// 6. Write Payload Length (int24)
		uint32Buf := make([]byte, 4)
		binary.BigEndian.PutUint32(uint32Buf, uint32(len(cipherData)))

		l, err := writer.Write(uint32Buf[1:])
		if err != nil {
			return 0, err
		}
		totalSize += uint32(l)

		slog.Debug("checkpoint CreateNanoTDF", "payload_length", len(cipherData))

		// 7. Write Ciphertext
		l, err = writer.Write(cipherData)
		if err != nil {
			return 0, err
		}
		totalSize += uint32(l)

		return totalSize, nil
	}
}

// ============================================================================================================
// Factory: LoadNanoTDF
// ============================================================================================================

// NewNanoTDFLoader returns a function that initializes a NanoTDFReader.
func NewNanoTDFLoader[C any](
	headerReader HeaderReader,
	rewrapper Rewrapper,
	cache KeyCache,
	decryptor Encryptor,
	allowListProvider func(C) AllowListChecker,
) func(context.Context, io.ReadSeeker, *C) (*NanoTDFReader[C], error) {

	return func(ctx context.Context, reader io.ReadSeeker, config *C) (*NanoTDFReader[C], error) {
		// 1. Parse Header
		header, headerBuf, err := headerReader.Read(reader)
		if err != nil {
			return nil, fmt.Errorf("header read failed: %w", err)
		}

		// 2. Validate AllowList
		kasURL, err := header.GetKasURL()
		if err != nil {
			return nil, fmt.Errorf("invalid kas url in header: %w", err)
		}

		checker := allowListProvider(*config)
		if checker.IsIgnored() {
			slog.WarnContext(ctx, "kasAllowlist is ignored, kas url is allowed", "kas_url", kasURL)
		} else if !checker.IsAllowed(kasURL) {
			return nil, fmt.Errorf("KasAllowlist: kas url %s is not allowed", kasURL)
		}

		// 3. Create Reader Object
		return &NanoTDFReader[C]{
			Reader:    reader,
			rewrapper: rewrapper,
			cache:     cache,
			decryptor: decryptor,
			Config:    config,
			Header:    header,
			HeaderBuf: headerBuf,
		}, nil
	}
}

// ============================================================================================================
// NanoTDFReader Object
// ============================================================================================================

type NanoTDFReader[C any] struct {
	Reader    io.ReadSeeker
	Config    *C
	Header    HeaderInfo
	HeaderBuf []byte

	rewrapper   Rewrapper
	cache       KeyCache
	decryptor   Encryptor
	payloadKey  []byte
	obligations []string
}

func (n *NanoTDFReader[C]) Init(ctx context.Context) error {
	if n.payloadKey != nil {
		return nil
	}
	return n.unwrapKey(ctx)
}

func (n *NanoTDFReader[C]) Obligations(ctx context.Context) ([]string, error) {
	if len(n.obligations) > 0 {
		return n.obligations, nil
	}

	err := n.Init(ctx)
	if len(n.obligations) > 0 {
		return n.obligations, nil
	}
	return []string{}, err
}

func (n *NanoTDFReader[C]) Decrypt(ctx context.Context, writer io.Writer) (int, error) {
	if n.payloadKey == nil {
		if err := n.unwrapKey(ctx); err != nil {
			return 0, err
		}
	}

	// 1. Read Payload Length (int24)
	payloadLengthBuf := make([]byte, 4)
	_, err := n.Reader.Read(payloadLengthBuf[1:])
	if err != nil {
		return 0, fmt.Errorf("read length failed: %w", err)
	}

	payloadLength := binary.BigEndian.Uint32(payloadLengthBuf)
	slog.DebugContext(ctx, "decrypt", "payload_length", payloadLength)

	// 2. Read Ciphertext
	cipherData := make([]byte, payloadLength)
	_, err = n.Reader.Read(cipherData)
	if err != nil {
		return 0, fmt.Errorf("read payload failed: %w", err)
	}

	// 3. Determine Tag Size
	tagSize, err := n.decryptor.GetTagSize(n.Header.GetCipherEnum())
	if err != nil {
		return 0, fmt.Errorf("get tag size failed: %w", err)
	}

	// 4. Decrypt
	plaintext, err := n.decryptor.Decrypt(cipherData, n.payloadKey, tagSize)
	if err != nil {
		return 0, err
	}

	// 5. Write Output
	writeLen, err := writer.Write(plaintext)
	if err != nil {
		return 0, err
	}

	return writeLen, nil
}

func (n *NanoTDFReader[C]) unwrapKey(ctx context.Context) error {
	if n.cache != nil {
		if key, found := n.cache.Get(n.HeaderBuf); found {
			n.payloadKey = key
			return nil
		}
	}

	url, err := n.Header.GetKasURL()
	if err != nil {
		return err
	}

	key, obs, err := n.rewrapper.Rewrap(ctx, n.HeaderBuf, url)
	if err != nil {
		return err
	}

	n.payloadKey = key
	n.obligations = obs

	if n.cache != nil {
		n.cache.Store(n.HeaderBuf, key)
	}

	return nil
}
