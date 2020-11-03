# go-blob-encryption (blobcrypt)

blobcrypt allows encryption and decryption of large files using the original file's SHA256 hash as the key. Any user with the file's original SHA256 hash may decrypt known files that are encrypted using this method.

Some circumstances where this may be useful:
- A user has or once had a copy of the original file, as in a backup or semi-private cache.
- The hash is disclosed to specific users, as a way of sharing or selling access to the content.
- The hash is published as a safety measure, to ensure the integrity and safety of downloads.
- The hash is part of a commitment scheme, and later publication of the encrypted file discloses the content to a limited audience.

Encrypted files produced with this library depend only on the input; An identical source file always produces an identical encrypted file. For backups, this allows deduplication across users and easy sharing – the file's contents are opaque to the service provider or any user who does not already have the original file, and the file can be securely shared by providing its hash and a reference to the encrypted file.

### Pros

- Shareability:
  - If an encrypted file is available at a public URL, disclosing the original file's hash allows new users to decode it.
  - The file is tamperproof, as any change to the bytes causes decoding to fail, and decrypted output may be checked against the original hash.
- Offloadable:
  - With the original hash, files can be recovered from public sources on-demand, allowing local copies to be removed.
  - Unique files like personal documents, photos, etc. are secure, as no other file will produce the same encryption parameters.
- Files can be deduplicated across users. Every user who encodes a particular file produces exactly the same bytes.

### Cons

- If someone has an original file or its SHA256 hash, they can tell if an encrypted file contains it.
- Each file produces a unique hash / key. Unlike a password, these keys must be retained and change when the file changes.

## File Format

blobcrypt encrypts files using 256-bit AES CTR, with an appended SHA512 HMAC of the encrypted bytes.

The encryption key `key` is `SHA256(input)`, the SHA256 hash of the entire unencrypted input.

The initialization vector `iv` is `SHA256(key)`; The CTR cipher is initialized with only the first 16 bytes of this value.

The HMAC suffix is calculated over the output (encrypted) bytes using sha512, with a key of `SHA256(iv)`.

## Command Line Usage

The provided [command line tool](cli/blobcrypt/) may be compiled using the project's Makefile; Use `make install` for installation.

```sh
# Create an encrypted copy of file.txt in ./encrypted/file.txt
# The sha256 hash will be saved in ./encrypted/file.txt.key
> blobcrypt file.txt ./encrypted/

# Same as above, but specify everything explicitly
> blobcrypt -keyfile encrypted/file.txt.key -encode file.txt encrypted/file.txt

# Check that key is correct for an encrypted file; Key is inferred to be at encrypted/file.txt.key
# This is typically unnecessary, as -decrypt calls the same code paths before decryption
> blobcrypt -check encrypted/file.txt

# Decrypt the encoded file to stdout; Key is inferred to be at encrypted/file.txt.key
> blobcrypt -decrypt encrypted/file.txt

# Decrypt, providing the hash directly and specifying an output file
> blobcrypt -decrypt -key "dc1304c90b95cf77e6e2291402f1a51927a756614f96bf92da3c3e391cf46b74" encrypted/file.txt decrypted.txt
```

## Usage Example

A complete example may be found in the [unit tests](blobcrypt_test.go)

```go
import blobcrypt "github.com/home-orbit/go-blob-encryption"

// Encrypt a small file to an in-memory buffer
func encryptFile(atPath string) ([]byte, error) {
  // Open input, which must be seekable.
  f, err := os.Open(atPath)
  if err != nil {
    return nil, err
  }
  
  // Derive the file's key
  key, err := blobcrypt.CalculateKey(f)
  if err != nil {
    return nil, err
  }
  
  // Create a writer
  writer, err := blobcrypt.NewWriter(f, key)
  if err != nil {
    return nil, err
  }
  
  // Write into a buffer and return its contents
  var buffer bytes.Buffer
  if err := writer.Encrypt(&buffer); err != nil {
    return nil, err
  }
  
  return buffer.Bytes(), nil
}
```
