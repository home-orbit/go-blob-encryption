package blobcrypt

import (
	"context"
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
	Source io.Reader
	Cipher cipher.Stream
	Error  error
}

// Stream starts a goroutine that sends blocks of enciphered content to a channel,
// blocking on backpressure. This method may only be called once.
// Returns a channel on which enciphered blocks will be streamed to the receiver.
// If an error occurs, the channel is closed and CipherStream's Error will be non-nil.
func (cs *CipherStream) Stream(ctx context.Context) chan []byte {
	// Channel capacity is reduced by 2 to allow for an active input and output buffer.
	channel := make(chan []byte, cipherStreamBufferCount-2)

	go func() {
		defer close(channel)
		// Writes to channel block when full, so we can use round-robin buffers.
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

			if l > 0 {
				// Encipher the filled part of buffer to Channel.
				// This is done before sending the buffer, since write bottlenecks are most common.
				filled := buf[:l]
				cs.Cipher.XORKeyStream(filled, filled)

				select {
				case <-ctx.Done():
					// Context was canceled by receiver; Return so we don't just block forever.
					return
				case channel <- filled:
					// Data sent to Channel. Continue normally.
					break
				}
			}

			// io.Read: "Callers should always process the n > 0 bytes returned before considering the error"
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				cs.Error = err
				return
			}
		}
	}()

	return channel
}
