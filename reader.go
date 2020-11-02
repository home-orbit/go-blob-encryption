package blobcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
)

// Reader decrypts the contents of an underlying io.Reader
type Reader struct {
	Source io.Reader
	Key    []byte
}

// NewReader returns a new Reader IFF source is valid and key matches.
func NewReader(source io.ReadSeeker, key []byte) (*Reader, error) {
	offset, err := CheckKey(source, key)
	if err != nil {
		return nil, err
	}
	return &Reader{
		Source: io.LimitReader(source, offset),
		Key:    key,
	}, nil
}

// Decrypt copies the decrypted content to the provided io.Writer.
func (r *Reader) Decrypt(w io.Writer) error {
	iv := shaSlice256(r.Key)

	blockCipher, err := aes.NewCipher(r.Key)
	if err != nil {
		return err
	}

	ctr := cipher.NewCTR(blockCipher, iv[:blockCipher.BlockSize()])

	const bufSize = 4096
	inBuf := make([]byte, bufSize)
	outBuf := make([]byte, bufSize)
	for {
		l, err := r.Source.Read(inBuf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// Error was returned and is not EOF
			return err
		}

		outSlice := outBuf[:l]
		ctr.XORKeyStream(outSlice, inBuf[:l])

		if _, err := w.Write(outSlice); err != nil {
			return err
		}
	}
	return nil
}
