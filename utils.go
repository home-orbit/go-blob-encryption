package blobcrypt

import "crypto/sha256"

func shaSlice256(input []byte) []byte {
	hash := sha256.Sum256(input)
	return hash[:]
}
