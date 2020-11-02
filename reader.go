package blobcrypt

import (
	"crypto/aes"
	"crypto/cipher"
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

	// Ensure that decryption runs in parallel with output.
	// This provides a minor speedup in casual tests, but is worth taking.
	cipherStream := NewCipherStream(r.Source, ctr)
	go cipherStream.Stream()

	// In the main routine, wait for blocks of encoded data to arrive, and write them to disk
	for buf := range cipherStream.Channel {
		if _, err := w.Write(buf); err != nil {
			return err
		}
	}

	// If cipherStream exited abnormally, return its error.
	return cipherStream.Error
}
