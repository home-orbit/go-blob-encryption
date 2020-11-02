package blobcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
)

const (
	defaultBufferSize = 4096
)

// Writer encrypts the contents of an underlying io.ReadSeeker
type Writer struct {
	Source io.ReadSeeker
	Key    []byte
}

// NewWriter computes the Key for source and returns a new Writer
func NewWriter(source io.ReadSeeker, key []byte) (*Writer, error) {
	if len(key) != sha256.Size {
		return nil, fmt.Errorf("Key size is incorrect")
	}
	return &Writer{Source: source, Key: key}, nil
}

// Encrypt encrypts the contents of the receiver to the output stream.
func (w *Writer) Encrypt(output io.Writer) error {
	blockCipher, err := aes.NewCipher(w.Key)
	if err != nil {
		return err
	}

	iv := shaSlice256(w.Key)
	hmacKey := shaSlice256(iv)

	ctr := cipher.NewCTR(blockCipher, iv[:blockCipher.BlockSize()])
	mac := hmac.New(sha512.New, hmacKey)

	buf := make([]byte, defaultBufferSize)
	for {
		l, err := w.Source.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// Error was returned and is not EOF
			return err
		}

		slice := buf[:l]
		// XORKeyStream transforms in-place if the arguments are the same.
		ctr.XORKeyStream(slice, slice)

		if _, err := mac.Write(slice); err != nil {
			return err
		}
		if _, err := output.Write(slice); err != nil {
			return err
		}
	}
	_, err = output.Write(mac.Sum(nil))
	return err
}
