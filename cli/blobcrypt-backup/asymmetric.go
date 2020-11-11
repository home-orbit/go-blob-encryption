package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

const (
	minRSAKeySize = 512 // Minimum key size in bytes, equivalent to 4096 bits
)

// EncryptKey writes the given symmetric key to path with OAEP encryption, using pubkey.
// This allows random encryption keys for secure files, like the keystore, to be included
// in backups, since only the private key holder can decrypt them.
//
// OAEP params use a sha256 hash for the random oracle, and crypto/rand.Reader as the entropy source.
func EncryptKey(key []byte, path string, pubkey *rsa.PublicKey) error {
	const label = "symmetric-key"
	output, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubkey, key, []byte(label))
	if err != nil {
		return err
	}

	return ioutil.WriteFile(path, output, 0644)
}

// LoadPublicKey reads and validates an RSA public key from the file at path.
// If the key is less than 4096 bits, an error is returned.
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, pemBytes := pem.Decode(pemBytes)
	for ; block != nil; block, pemBytes = pem.Decode(pemBytes) {
		switch block.Type {
		case "RSA PUBLIC KEY":
		case "PUBLIC KEY":
			// Decode an RSA public key
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			rsaKey, ok := key.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("Invalid key")
			}
			if rsaKey.Size() < minRSAKeySize {
				return nil, fmt.Errorf("RSA Public Key must be at least %d bits", minRSAKeySize*8)
			}
			return rsaKey, nil
		}
	}

	return nil, fmt.Errorf("Key not found in file %s", path)
}
