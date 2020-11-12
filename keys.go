package blobcrypt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
)

const (
	// KeySize is the size of a symmetric encryption key (equal to sha256.Size)
	KeySize = sha256.Size
)

// ComputeKey returns the encryption key to be used for an unencrypted source,
// or an error if one occurred.
//
// The convergence secret cs is inculded in the key calculation to enhance security.
// For highly entropic files (photos & video) cs is generally not critical and may be shared.
// For other large files like software downloads, it may be possible for an attacker to
// identify an encrypted copy of a known file if cs is omitted; This may or may not matter.
// For files that are small, sensitive, or may contain unexpectedly low entropy
// (eg, a large PDF with just a few sensitive characters in it, like a bank PIN)
// a strong convergence secret like a GUID should always be used.
func ComputeKey(source io.ReadSeeker, cs string) ([]byte, error) {
	sha := sha256.New()
	sha.Write([]byte(cs))
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

	const macSize = int64(sha512.Size)
	mac := hmac.New(sha512.New, hmacKey)

	// Skip to the correct number of bytes from the end of the file.
	trailerPos, err := source.Seek(-macSize, io.SeekEnd)
	if err != nil {
		return 0, err
	}

	// Read the embedded HMAC value
	embeddedHMAC := make([]byte, macSize)
	// Docs indicate it's possible to get correct data and EOF in a single call.
	if l, err := source.Read(embeddedHMAC); l != len(embeddedHMAC) && err != nil {
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
	if !hmac.Equal(bodyHMAC, embeddedHMAC) {
		return 0, fmt.Errorf("File signature invalid (HMAC)")
	}

	// Reset source position before returning trailer offset
	_, err = source.Seek(0, io.SeekStart)
	return trailerPos, err
}
