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

The encryption key `key` is `SHA256(cs || input)`, where cs is the convergence secret, and input is the original file. The default convergence secret is zero bytes, so in the absence of a convergence secret, the key is the SHA256 hash of the source file.

The initialization vector `iv` is `SHA256(key)`; The CTR cipher is initialized with only the first 16 bytes of this value.

The HMAC suffix is calculated over the output (encrypted) bytes using sha512, with a key of `SHA256(iv)`.

### Convergence Secrets

When encrypting files, an optional prefix to the input may be supplied, called a convergence secret. Whether and how a convergence secret is used affects a trade-off between shareability and deduplication, and security.

Sharing files' encryption keys does not affect the security of the convergence secret, but the secret must have enough entropy to prevent brute-force attacks; UUIDs are recommended.

With the same convergence secret, all copies of a source file produce identical encrypted bytes. This is useful to deduplicate storage and prevent multiple uploads of the same file, but may allow an attacker who has a copy of the original file or its hash to verify that an encrypted file corresponds to it. In some circumstances, this could be framed as an attack. In other circumstances, giving someone a short hash code to allow access to an encrypted document is called *sharing*.

- **None**: Globally, all encrypted copies of the same file produce the exact same encrypted output. Large and highly unique files, like photos or videos taken by the user, can be shared easily with almost no security impact. If a copy of the original file is stolen, however, an attacker could verify its authenticity by proving it's the same as the encrypted copy.
- **Shared**: A group of users uses the same convergence secret. This ensures that if each of those users backs up the same file, storage can be deduplicated. Any user in the group can verify the identity of another user's accessible encrypted files if they have the original.
- **Per-user**: A user keeps one UUID and uses it on many computers. Her encrypted files will always be distinct from other users' files, but the same files on multiple computers – especially software updates, photos, and videos, can be deduplicated. An attacker would need the private convergence key to identify known files.
- **Per-file**: A user generates and stores a random secret for each new file. Even multiple copies of the same file on the same computer can't be deduplicated or identified without the unique key for that particular copy.

> Convergent Encryption carries a risk of a brute-force attack on a rare but potentially critical type of file, with *unexpectedly low entropy*. For a highly contrived case, imagine that a bank has sent you a 10MB PDF with a 4-digit recovery PIN and no other identifying info, and the PDF itself is password-protected with your ATM PIN or the last 4 digits of your social security number. *This file is incredibly dangerous! If you encounter a file like this in real life, destroy all copies immediately.*
>
> Regardless, if an attacker has the convergence secret or none was used, only four bytes differ between copies, plus four digits of the password. An attacker merely needs any version of the original file, perhaps one provided by the bank for their own account. Depending on particulars, they might need to encrypt 100 million modified copies of that file – 10,000 copies for all the different recovery PINs, and then 10,000 copies of each of those files using every possible 4-digit password. This can be done fast and in-memory, saving just the hashes of the final documents to a rainbow table. At this point, the attacker can simply look up the PIN and document password for an encrypted copy.
>
> This is most relevant when the convergence secret is not used, but it could also appear in a corporate context where secrets are shared; For example, storing unexpectedly low-entropy documents from HR might allow a malicious employee to discover information about salary, benefits, recovery passwords, or other protected information. For this reason, it is strongly recommended that per-user or random secrets be used for private documents that contain text.
>
> Additional discussion can be found at [Tahoe-LAFS](https://tahoe-lafs.org/hacktahoelafs/drew_perttula.html)


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
> blobcrypt -decrypt \
  -key "dc1304c90b95cf77e6e2291402f1a51927a756614f96bf92da3c3e391cf46b74" \
  encrypted/file.txt decrypted.txt
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
  
  // Derive the file's key, without using a convergence secret
  // This is OK for highly-entropic large media that may be shared, like photos
  key, err := blobcrypt.CalculateKey(f, "")
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
