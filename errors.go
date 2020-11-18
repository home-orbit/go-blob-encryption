package blobcrypt

// Error implements Error
type Error string

func (e Error) Error() string {
	return string(e)
}

const (
	// HMACInvalid indicates that an HMAC check has failed.
	HMACInvalid = Error("HMAC Invalid")
)
