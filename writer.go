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
// On successful return, Writer's HMAC will be set to the HMAC of the output.
func (w *Writer) Encrypt(output io.Writer) ([]byte, error) {
	blockCipher, err := aes.NewCipher(w.Key)
	if err != nil {
		return nil, err
	}

	iv := shaSlice256(w.Key)
	hmacKey := shaSlice256(iv)

	// Configure a cancelable context, ensuring goroutines won't be leaked on early return.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cipherStream := CipherStream{
		Source: w.Source,
		Cipher: cipher.NewCTR(blockCipher, iv[:blockCipher.BlockSize()]),
	}

	// Encrypt input file in parallel with output, and calculate HMAC as we go.
	mac := hmac.New(sha512.New, hmacKey)
	for buf := range cipherStream.Stream(ctx) {
		// According to documentation, Hash.Write never returns an error.
		mac.Write(buf)

		if _, err := output.Write(buf); err != nil {
			return nil, err
		}
	}

	// If cipherStream exited abnormally due to a read error, return it
	if err := cipherStream.Error; err != nil {
		return nil, err
	}

	// Otherwise, write the HMAC suffix
	hmacFinal := mac.Sum(nil)
	_, err = output.Write(hmacFinal)
	return hmacFinal, err
}
