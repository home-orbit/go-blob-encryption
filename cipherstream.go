package blobcrypt

import (
	"crypto/cipher"
	"errors"
	"io"
)

const (
	cipherStreamBufferCount = 3
	cipherStreamBufferSize  = 16384
)

// CipherStream may be run in a goroutine to stream enciphered blocks to its Channel.
type CipherStream struct {
	Source  io.Reader
	Cipher  cipher.Stream
	Channel chan []byte
	Error   error
}

// NewCipherStream creates a CipherStream that can stream ciphered blocks to its Channel
func NewCipherStream(source io.Reader, cipher cipher.Stream) *CipherStream {
	return &CipherStream{
		Source: source,
		Cipher: cipher,
		// Channel capacity always leaves room for an active input and ouptut buffer.
		// Channel may only have one consumer at a time or corruption may occur.
		Channel: make(chan []byte, cipherStreamBufferCount-2),
	}
}

// Stream sends the deciphered content of Source to Channel, blocking on backpressure.
// This method must be called in a separate goroutine from the consumer.
// Only one routine may consume Channel, and this method may only be called once.
// If an error occurs, Channel is closed and the receiver's Error will be non-nil.
func (cs *CipherStream) Stream() {
	defer close(cs.Channel)
	// Writes to cs.Channel block when full, so we can use round-robin buffers.
	// One buffer must be reserved for input and one for output at all times.
	var bufs [cipherStreamBufferCount][]byte
	for i := range bufs {
		bufs[i] = make([]byte, cipherStreamBufferSize)
	}

	for i := 0; ; i++ {
		// Choose a buffer that is free, round-robin style
		// Backpressure ensures this only executes when an idle buffer is available at i.
		buf := bufs[i%cipherStreamBufferCount]

		l, err := cs.Source.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			cs.Error = err
			return
		}

		// Encipher and send the filled part of buffer to Channel.
		// Enciphering is most efficient here, since bottlenecks in the write pipeline are common.
		filled := buf[:l]
		cs.Cipher.XORKeyStream(filled, filled)
		cs.Channel <- filled
	}
}
