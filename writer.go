package blobcrypt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
)

const (
	defaultBufferSize = 16384
)

// Writer encrypts the contents of an underlying io.ReadSeeker.
type Writer struct {
	Source io.ReadSeeker
	Key    []byte
}

// NewWriter creates a writer that encrypts source using key.
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

	// Configure a cancelable context, ensuring goroutines won't be leaked on early return.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctr := cipher.NewCTR(blockCipher, iv[:blockCipher.BlockSize()])
	mac := hmac.New(sha512.New, hmacKey)

	// Ensure that the actual encryption runs in parallel with output.
	// This is only a +30% speedup in casual tests, but is worth taking.
	cipherStream := CipherStream{Source: w.Source, Cipher: ctr}
	for buf := range cipherStream.Stream(ctx) {
		// According to documentation, Hash.Write never returns an error.
		mac.Write(buf)

		if _, err := output.Write(buf); err != nil {
			return err
		}
	}

	// If cipherStream exited abnormally due to a read error, return it
	if err := cipherStream.Error; err != nil {
		return err
	}

	// Otherwise, write the HMAC suffix
	_, err = output.Write(mac.Sum(nil))
	return err
}
