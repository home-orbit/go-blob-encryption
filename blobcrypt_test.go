package blobcrypt

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestRoundTrip ensures that the result of round-tripping a 1MB chunk of random bytes succeeds,
// and that the decoded result matches the original.
func TestRoundTrip(t *testing.T) {
	// Generate 1MB of random bytes
	randomBytes := make([]byte, 1<<20)
	if _, err := rand.Read(randomBytes); err != nil {
		t.Fatalf("%v reading random bytes", err)
	}
	input := bytes.NewReader(randomBytes)

	// Compute the source data's key
	key, err := ComputeKey(input)
	if err != nil {
		t.Fatalf("%v computing key", err)
	}

	// Create a writer to encrypt the data with key
	writer, err := NewWriter(input, key)
	if err != nil {
		t.Fatalf("%v creating Writer", err)
	}

	// Capture the encrypted output in a buffer
	var output bytes.Buffer
	if err := writer.Encrypt(&output); err != nil {
		t.Fatalf("%v encrypting input", err)
	}

	// Wrap the output bytes in a type that implements io.ReadSeeker
	outputReader := bytes.NewReader(output.Bytes())

	// Create a reader to decode the output buffer again using key
	reader, err := NewReader(outputReader, key)
	if err != nil {
		t.Fatalf("%v creating Reader", err)
	}

	// Decrypt the output into another buffer
	var decrypted bytes.Buffer
	if err := reader.Decrypt(&decrypted); err != nil {
		t.Fatalf("%v decrypting output", err)
	}

	// Ensure that the final result is equal to the original input
	if !bytes.Equal(decrypted.Bytes(), randomBytes) {
		t.Fatalf("Output did not match")
	}
}
