package blobcrypt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
)

// ComputeKey returns the encryption key to be used for an unencrypted source,
// or an error if one occurred.
func ComputeKey(source io.ReadSeeker) ([]byte, error) {
	sha := sha256.New()
	if _, err := io.Copy(sha, source); err != nil {
		return nil, err
	}
	hash := sha.Sum(nil)

	// Reset source position before returning the key
	_, err := source.Seek(0, io.SeekStart)
	return hash[:], err
}

// CheckKey checks an io.ReadSeeker (a file, etc.) for internal consistency,
// and ensures that the given key matches the embedded signature.
// A valid source has a trailer with an HMAC for the given key and the preceding, encrypted bytes.
//
// Returns the offset at which the validated, encrypted content ends, or an error if one occurred.
func CheckKey(source io.ReadSeeker, key []byte) (int64, error) {
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
