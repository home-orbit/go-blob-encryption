package blobcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
)

// Reader decrypts the contents of an underlying io.Reader
type Reader struct {
	Source io.Reader
	Key    []byte
}

// NewReader returns a new Reader IFF source is valid and key matches.
func NewReader(source io.ReadSeeker, key []byte) (*Reader, error) {
	offset, err := Validate(source, key)
	if err != nil {
		return nil, err
	}
	return &Reader{
		Source: io.LimitReader(source, offset),
		Key:    key,
	}, nil
}

// Validate checks an io.ReadSeeker (a file, etc.) to ensure that it is internally consistent.
// Valid files have a trailer containing an HMAC that is valid over the preceding, encrypted bytes.
//
// Returns the offset at which the valid, encrypted content ends, or an error if one occurred.
func Validate(source io.ReadSeeker, key []byte) (int64, error) {
	iv := shaSlice256(key)
	hmacKey := shaSlice256(iv)

	mac := hmac.New(sha512.New, hmacKey)
	macSize := int64(mac.Size())

	// Skip to the correct number of bytes from the end of the file.
	trailerPos, err := source.Seek(-macSize, io.SeekEnd)
	if err != nil {
		return 0, err
	}

	// Read the embedded HMAC value
	embeddedHMAC := make([]byte, mac.Size())
	if _, err := source.Read(embeddedHMAC); err != nil {
		return 0, err
	}

	// Return to the beginning of the file and start scanning
	if _, err = source.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}

	// Use a LimitReader that stops before the final HMAC suffix
	bodyReader := io.LimitReader(source, trailerPos)
	if _, err := io.Copy(mac, bodyReader); err != nil {
		return 0, err
	}
	bodyHMAC := mac.Sum(nil)

	// Require the embedded HMAC to match the one we just calculated.
	if !bytes.Equal(bodyHMAC, embeddedHMAC) {
		return 0, fmt.Errorf("File signature invalid (HMAC)")
	}

	// Reset source position before returning trailer offset
	_, err = source.Seek(0, io.SeekStart)
	return trailerPos, err
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
