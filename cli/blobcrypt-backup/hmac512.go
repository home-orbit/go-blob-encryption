package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	blobcrypt "github.com/home-orbit/go-blob-encryption"
)

// HMAC512 is a fixed-length byte slice allowing HMACs to be used as keys.
type HMAC512 [blobcrypt.HMACSize]byte

// URLChars returns the first n chars of the URL-compatible, unpadded base64 encoding of the receiver.
func (h HMAC512) URLChars(n int) string {
	return base64.RawURLEncoding.EncodeToString(h[:])[:n]
}

// MarshalJSON implements json.Marshaler
func (h HMAC512) MarshalJSON() ([]byte, error) {
	return json.Marshal(h[:])
}

// UnmarshalJSON implements json.Unmarshaler
func (h *HMAC512) UnmarshalJSON(data []byte) error {
	raw := make([]byte, len(h))
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if copy(h[:], raw) != len(h) {
		return fmt.Errorf("Incorrect hash length in JSON")
	}
	return nil
}

func (h HMAC512) String() string {
	return hex.EncodeToString(h[:])
}
