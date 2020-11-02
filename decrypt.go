package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

func decryptFile(infile, outfile, sha256String string) error {
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

	key, err := hex.DecodeString(sha256String)
	if err != nil {
		return err
	}
	iv := shaSlice256(key)
	hmacKey := shaSlice256(iv)

	var inBodyReader io.Reader
	{
		mac := hmac.New(sha512.New, hmacKey)
		// Stat the input file and read all but the last len(hmac) bytes.
		info, err := in.Stat()
		if err != nil {
			return err
		}

		macSize := int64(mac.Size())
		// Use a LimitReader that stops before the final HMAC suffix
		encReader := io.LimitReader(in, info.Size()-macSize)
		if _, err := io.Copy(mac, encReader); err != nil {
			return err
		}
		hmacResult := mac.Sum(nil)

		// Seek to the HMAC suffix, relative to the end of the file, and read it
		if _, err := in.Seek(-macSize, 2); err != nil {
			return err
		}
		// Read the embedded HMAC value
		hmacFile := make([]byte, mac.Size())
		if _, err := in.Read(hmacFile); err != nil {
			return err
		}

		// Require the embedded HMAC to match the one we just calculated.
		if !bytes.Equal(hmacFile, hmacResult) {
			return fmt.Errorf("File signature invalid (HMAC)")
		}

		// Reset input
		if _, err := in.Seek(0, 0); err != nil {
			return err
		}
		// When decrypting, we also need to stop before the suffix again.
		inBodyReader = io.LimitReader(in, info.Size()-macSize)
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	ctr := cipher.NewCTR(blockCipher, iv[:blockCipher.BlockSize()])

	const bufSize = 4096
	inBuf := make([]byte, bufSize)
	outBuf := make([]byte, bufSize)
	for {
		l, err := inBodyReader.Read(inBuf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// Error was returned and is not EOF
			return err
		}

		outSlice := outBuf[:l]
		ctr.XORKeyStream(outSlice, inBuf[:l])

		if _, err := out.Write(outSlice); err != nil {
			return err
		}
	}
	return nil
}
