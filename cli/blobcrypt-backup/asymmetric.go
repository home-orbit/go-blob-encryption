package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

const (
	minRSAKeySize = 512 // Minimum key size in bytes, equivalent to 4096 bits

	// SymmetricKeyLabel is the label value required for OAEP key encryption
	SymmetricKeyLabel = "symmetric-key"
)

// EncryptKey returns the given symmetric key encrypted with OAEP, using pubkey.
// This allows random encryption keys for secure files, like the manifest, to be included
// in backups, since only the private key holder can decrypt them.
//
// OAEP params use a sha256 hash for the random oracle, and crypto/rand.Reader as the entropy source.
func EncryptKey(key []byte, pub *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, key, []byte(SymmetricKeyLabel))
}

// DecryptKey returns the original symmetric key from an OAEP-encrypted ciphertext,
// using the given private key. This allows secure recovery of random encryption
// keys that were enciphered with the corresponding public key.
//
// The ciphertext must be encrypted with matching OAEP params; sha256 hash for the random oracle,
// and label equal to SymmetricKeyLabel.
func DecryptKey(ciphered []byte, priv *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ciphered, []byte(SymmetricKeyLabel))
}
