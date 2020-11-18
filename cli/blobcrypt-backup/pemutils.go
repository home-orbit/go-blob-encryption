package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh/terminal"
)

// LoadPEMBlock handles PEM Block decryption when necessary,
// prompting the user interactively for the password.
// For unencrypted blocks, always returns block.Bytes and nil error.
func LoadPEMBlock(block *pem.Block, prompt string) ([]byte, error) {
	if !x509.IsEncryptedPEMBlock(block) {
		return block.Bytes, nil
	}
	fmt.Printf("%s: ", prompt)
	pw, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, err
	}
	return x509.DecryptPEMBlock(block, pw)
}

// LoadPublicKey reads and validates an RSA public key from the file at path.
// If the key is less than 4096 bits, an error is returned.
// If the PEM Block containing the public key is encrypted, the user will be
// prompted for the file's password.
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
			pwPrompt := fmt.Sprintf("Enter Passphrase for %s", filepath.Base(path))
			body, err := LoadPEMBlock(block, pwPrompt)
			if err != nil {
				return nil, err
			}
			key, err := x509.ParsePKIXPublicKey(body)
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

// LoadPrivateKey reads and validates an RSA public key from the file at path.
// If the key is less than 4096 bits, an error is returned.
// If the PEM block containing the private key is encrypted, the user will be
// prompted for the file's passphrase.
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, pemBytes := pem.Decode(pemBytes)
	for ; block != nil; block, pemBytes = pem.Decode(pemBytes) {
		switch block.Type {
		case "RSA PRIVATE KEY", "PRIVATE KEY":
			// Decode an RSA private key
			pwPrompt := fmt.Sprintf("Enter Passphrase for %s", filepath.Base(path))
			body, err := LoadPEMBlock(block, pwPrompt)
			if err != nil {
				return nil, err
			}
			key, err := x509.ParsePKCS8PrivateKey(body)
			if err != nil {
				// Rather than forcing a specific format per block.Type string,
				// recover by trying PKCS1 after the preferred parse failure.
				if pkcs1Key, pkcs1Err := x509.ParsePKCS1PrivateKey(body); pkcs1Err == nil {
					key, err = pkcs1Key, pkcs1Err
				} else {
					// Return the original (PKCS8) error
					return nil, err
				}
			}
			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("Invalid key")
			}
			if rsaKey.Size() < minRSAKeySize {
				return nil, fmt.Errorf("RSA Private Key must be at least %d bits", minRSAKeySize*8)
			}
			return rsaKey, nil
		}
	}

	return nil, fmt.Errorf("Key not found in file %s", path)
}
