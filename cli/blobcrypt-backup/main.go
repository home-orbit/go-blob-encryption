package main

import (
	"crypto/hmac"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	blobcrypt "github.com/home-orbit/go-blob-encryption"
)

/* This is a command-line interface to create and restore backups using convergent encryption.
 * This consists of a several phases:
 * - Scanning all the files in the source directory, matching them to convergence keys as needed
 * - Checking os.FileInfo for those files, to heuristically skip unchanged files
 * - Producing HMAC keys by reading the contents of files on the local filesystem
 * - Checking which HMAC keys are not present in the backup set
 * - Writing the encrypted contents of missing files to the backup set
 */

const (
	defaultKeystoreName = "blobcrypt-keystore.json"
	// Filenames use 40 base64 chars for 240 bits of collision resistance
	// On case-insensitive filesystems, this is slightly less than 210 bits.
	filenameLen = 40
)

// logFatal logs formatted output to Stderr and exits with an error code of 1.
func logFatal(format string, values ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}

func main() {
	// Parse command-line arguments. By default, encrypt the file at arg[0]
	flags := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	userHomeDir, _ := os.UserHomeDir()
	keyfile := flags.String("keyfile", filepath.Join(userHomeDir, defaultKeystoreName), "Path to the keystore file.")
	pubkey := flags.String("pubkey", "", "Path to an RSA public key PEM. When present, keystore is added to the backup set using OAEP encryption")

	flags.Parse(os.Args[1:])

	if flags.NArg() < 2 {
		flags.Usage()
		fmt.Println(`Source and output dirs must be specified.`)
		os.Exit(1)
	}

	inPath, err := filepath.Abs(flags.Arg(0))
	if err != nil {
		panic(err)
	}

	outPath, err := filepath.Abs(flags.Arg(1))
	if err != nil {
		panic(err)
	}
	os.MkdirAll(outPath, 0755)

	// TODO: Read secrets from a configuration file
	scanner := Scanner{
		Secrets: make(map[string]string),
	}

	// Scan to get os.FileInfo and the Convergence Secret for the new file set.
	results, err := scanner.Scan(inPath)
	if err != nil {
		panic(err)
	}

	// Load the keystore from disk
	keystore := Keystore{
		Entries: make(map[LocalHash]KeystoreEntry),
	}
	keystore.Load(*keyfile)

	// Match the scanned results to entries in the file
	entries, err := keystore.Resolve(results)
	if err != nil {
		panic(err)
	}

	// Get prospective changeset containing items to update or delete
	diff := keystore.Diff(inPath, entries)

	if diff.IsEmpty() {
		fmt.Println("No changes detected.")
		os.Exit(0)
	}

	// Create a channel to send KeystoreEntry structs to a worker pool
	updates := make(chan interface{})
	go func() {
		defer close(updates)
		// Send each change from the diff to the worker pool channel
		for _, updated := range diff.Change {
			updates <- updated
		}
	}()

	// Run a set of parallel workers and collect their return values
	errs := RunWorkers(0, updates, func(i interface{}) interface{} {
		// func(KeystoreEntry) returns error or nil
		entry, isEntry := i.(KeystoreEntry)
		if !isEntry {
			return fmt.Errorf("Unrecognized Input: %v", i)
		}
		filename := entry.HMAC.URLChars(filenameLen)

		fmt.Printf("Updating %s (%s)\n", filename, entry.Path)

		// Check if the file needs to be backed up, looking for its unique filename in outPath.
		outFilePath := filepath.Join(outPath, filename)

		if _, err := os.Stat(outFilePath); os.IsNotExist(err) {
			// Encrypt files that don't exist in the output directory
			sourceFile, err := os.Open(entry.Path)
			if err != nil {
				return err
			}

			outFile, err := os.Create(outFilePath)
			if err != nil {
				return err
			}

			writer := blobcrypt.Writer{
				Source: sourceFile,
				Key:    entry.Key,
			}

			// TODO: Write output files atomically
			outputHMAC, err := writer.Encrypt(outFile)
			if !hmac.Equal(entry.HMAC[:], outputHMAC) {
				return err
			}
		}
		return nil
	})

	// Log any errors once the worker pool exits
	if len(errs) > 0 {
		for _, err := range errs {
			fmt.Fprintln(os.Stderr, err)
		}
		logFatal("Errors occurred, not updating keystore.")
	}

	// The 'Remove' part of the diff is not yet actionable; We must commit first, then filter for garbage.
	keystore.Commit(diff)
	if err := keystore.Save(*keyfile); err != nil {
		logFatal("Could not update Keystore file: %v", err)
	}

	if *pubkey != "" {
		// Encrypt keystore with a fully random key, and write a copy of that key
		// to a corresponding file with RSA OAEP asymmetric encryption.
		// Only the private key holder may decrypt the random key used to access the keystore.

		// TODO: Provide options for the keystore and/or its keyfile to be placed in arbitrary location(s).

		// Load the public key from the given file. Key must be at least minRSAKeySize.
		rsaPubkey, err := LoadPublicKey(*pubkey)
		if err != nil {
			logFatal(err.Error())
		}

		// Read from crypto/rand.Reader to create a random symmetric key.
		randomKey := make([]byte, blobcrypt.KeySize)
		if n, err := rand.Reader.Read(randomKey); n != blobcrypt.KeySize {
			logFatal("Could not read enough random bytes for key")
		} else if err != nil {
			logFatal(err.Error())
		}

		dstPath := filepath.Join(outPath, "index")
		dstKeyPath := filepath.Join(outPath, "index.key")

		// First, encrypt the index key to a file.
		// If this fails, there's no point in encrypting keystore with it.
		if err := EncryptKey(randomKey, dstKeyPath, rsaPubkey); err != nil {
			logFatal(err.Error())
		}

		sourceFile, err := os.Open(*keyfile)
		if err != nil {
			logFatal(err.Error())
		}

		outFile, err := os.Create(dstPath)
		if err != nil {
			logFatal(err.Error())
		}

		writer := blobcrypt.Writer{
			Source: sourceFile,
			Key:    randomKey,
		}

		// TODO: Write output files atomically
		_, err = writer.Encrypt(outFile)
		if err != nil {
			logFatal(err.Error())
		}
	}

	// Now that keystore is current, get a list of all HMACs that are still valid.
	// Remember that files may exist in the backup set that are not part of the current directory.
	for _, entry := range keystore.GarbageCollectable(diff.Remove) {
		outFilePath := filepath.Join(outPath, entry.HMAC.URLChars(filenameLen))
		_ = os.Remove(outFilePath)
		fmt.Printf("Removed %s (%s)\n", entry.HMAC.URLChars(filenameLen), entry.Path)
	}
}
