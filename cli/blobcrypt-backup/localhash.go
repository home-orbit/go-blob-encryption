package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// LocalHash is a fixed-length byte slice holding a SHA256 hash.
// It allows that hash to be used directly as a map key.
type LocalHash [sha256.Size]byte

// MarshalJSON implements json.Marshaler
func (h LocalHash) MarshalJSON() ([]byte, error) {
	return json.Marshal(h[:])
}

// UnmarshalJSON implements json.Unmarshaler
func (h *LocalHash) UnmarshalJSON(data []byte) error {
	raw := make([]byte, len(h))
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if copy(h[:], raw) != len(h) {
		return fmt.Errorf("Incorrect hash length in JSON")
	}
	return nil
}

func (h LocalHash) String() string {
	return hex.EncodeToString(h[:])
}

// Set sets the receiver to the SHA256 hash of local filesystem state, an absolute path,
// and the given convergence secret, or an error if one occurred.
// This method is conservative and could produce different modification codes for unchanged files.
func (h *LocalHash) Set(path, cs string, info os.FileInfo) error {
	if info == nil {
		return fmt.Errorf("Cannot generate LocalHash without a valid os.FileInfo")
	}

	modTimeBytes, err := info.ModTime().MarshalBinary()
	if err != nil {
		return err
	}
	size := info.Size()
	var sizeBytes = make([]byte, binary.Size(size))
	binary.PutVarint(sizeBytes, size)

	hash := sha256.New()
	// hash.Write never returns an error (per Docs)
	hash.Write([]byte(cs))
	hash.Write([]byte{0})
	hash.Write([]byte(path))
	hash.Write([]byte{0})
	hash.Write(modTimeBytes)
	hash.Write([]byte{0})
	hash.Write(sizeBytes)

	// Both slices have the same fixed size; ignore returned length.
	_ = copy(h[:], hash.Sum(nil))
	return nil
}

// Reset resets the receiver to the zero value.
func (h *LocalHash) Reset() {
	*h = LocalHash{}
}
