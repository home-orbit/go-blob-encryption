package blobcrypt

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"io"
)

// Reader decrypts the contents of an underlying io.Reader
type Reader struct {
	Source io.Reader
	Key    []byte
}

// NewReader returns a new Reader IFF source is valid and key matches.
func NewReader(source io.ReadSeeker, key []byte) (*Reader, error) {
	offset, err := CheckKey(source, key)
	if err != nil {
		return nil, err
	}
	return &Reader{
		Source: io.LimitReader(source, offset),
		Key:    key,
	}, nil
}

// Decrypt copies the decrypted content to the provided io.Writer.
func (r *Reader) Decrypt(w io.Writer) error {
	iv := shaSlice256(r.Key)

	blockCipher, err := aes.NewCipher(r.Key)
	if err != nil {
		return err
	}

	// Configure a cancelable context, ensuring goroutines won't be leaked on early return.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cipherStream := CipherStream{
		Source: r.Source,
		Cipher: cipher.NewCTR(blockCipher, iv[:blockCipher.BlockSize()]),
	}

	// Decrypt in parallel with output.
	for buf := range cipherStream.Stream(ctx) {
		if _, err := w.Write(buf); err != nil {
			return err
		}
	}

	// If cipherStream exited abnormally, return its error.
	return cipherStream.Error
}

// TailExcludingReader always withholds a fixed number of trailing bytes.
// After EOF is reached, the tail bytes remain in the tail buffer.
type TailExcludingReader struct {
	io.Reader
	tail     bytes.Buffer
	tailSize int
}

func (ter *TailExcludingReader) Read(into []byte) (int, error) {
	// Read the correct number of bytes from the embedded reader, but keep tail full
	// at all times and return EOF when the end is reached, leaving tail full.

	// Read until the buffer contains (len(into) + tailSize) bytes
	readSize := len(into) + ter.tailSize - ter.tail.Len()
	_, err := io.CopyN(&ter.tail, ter.Reader, int64(readSize))
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	outLen := ter.tail.Len() - ter.tailSize
	if outLen > 0 {
		// Return enough bytes that the buffer is left with tailSize bytes at all times.
		// Use a slice to fill the buffer only with the bytes we aren't reserving
		outSlice := into
		// Ensure we aren't overflowing the output buffer ("this should never happen")
		if len(outSlice) > outLen {
			outSlice = outSlice[:outLen]
		}
		return ter.tail.Read(outSlice)
	}
	// There aren't enough non-tail bytes to return any to the caller.
	// Return err here so that EOF will be propagated when it is encountered.
	return 0, err
}

// DecryptAndCheckKey allows decryption and authentication of non-seekable input.
// The contents of source must fit in memory.
//
// Whenever possible, a Reader should be used instead; Reader does not buffer any
// decrypted data until authentication has passed, and is therefore more secure.
//
// Returns HMACInvalid and a nil reader if content authentication fails.
func DecryptAndCheckKey(source io.Reader, key []byte) (io.Reader, error) {
	iv := shaSlice256(key)
	hmacKey := shaSlice256(iv)

	// We want to buffer the last 512 bytes of the file, and never return them.
	tailExcluder := &TailExcludingReader{
		Reader:   source,
		tailSize: HMACSize,
	}

	mac := hmac.New(sha512.New, hmacKey)
	macTee := io.TeeReader(tailExcluder, mac)

	// Create a Reader that decrypts from macTee(+tailExcluder) using key
	reader := Reader{Source: macTee, Key: key}

	// Temporarily store the decrypted output into a buffer
	var buf bytes.Buffer
	if err := reader.Decrypt(&buf); err != nil {
		return nil, err
	}

	// We can now access the calculated and embedded HMACs from the passthrough readers.
	embeddedHMAC := tailExcluder.tail.Bytes()
	calculatedHMAC := mac.Sum(nil)
	if hmac.Equal(embeddedHMAC, calculatedHMAC) {
		return &buf, nil
	}
	// Erase the buffer. Don't wait for GC.
	buf.Reset()
	// Return an empty buffer and an error
	return nil, HMACInvalid
}
