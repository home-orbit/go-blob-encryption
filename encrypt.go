package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"os"
)

func encryptFile(infile, outfile, outkeyfile string) error {
	in, err := os.Open(infile)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(outfile)
	if err != nil {
		return err
	}
	defer out.Close()

	var key []byte
	{
		sha := sha256.New()
		if _, err := io.Copy(sha, in); err != nil {
			return err
		}
		hash := sha.Sum(nil)
		key = hash[:]
		// Reset input
		if _, err := in.Seek(0, 0); err != nil {
			return err
		}
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := shaSlice256(key)
	ctr := cipher.NewCTR(blockCipher, iv[:blockCipher.BlockSize()])

	hmacKey := shaSlice256(iv)
	mac := hmac.New(sha512.New, hmacKey)

	const bufSize = 4096
	inBuf := make([]byte, bufSize)
	outBuf := make([]byte, bufSize)
	for {
		l, err := in.Read(inBuf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// Error was returned and is not EOF
			return err
		}

		outSlice := outBuf[:l]
		ctr.XORKeyStream(outSlice, inBuf[:l])

		if _, err := mac.Write(outSlice); err != nil {
			return err
		}
		if _, err := out.Write(outSlice); err != nil {
			return err
		}
	}
	out.Write(mac.Sum(nil))

	// Store the key as hex, for compatibility and safety.
	hexKey := hex.EncodeToString(key) + "\n"
	return ioutil.WriteFile(outkeyfile, []byte(hexKey), 0600)
}
