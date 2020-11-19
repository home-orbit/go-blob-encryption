package main

import (
	"archive/tar"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	blobcrypt "github.com/home-orbit/go-blob-encryption"
)

// BackupMain is the main function when the first CLI argument is "backup".
func BackupMain(args []string) error {
	flags := flag.NewFlagSet("backup", flag.ContinueOnError)
	keycache := flags.String("keycache", keyCacheName, "Path to the local cache of keys for incremental backups. If this is a relative path, it is relative to SOURCE.")
	pubkey := flags.String("pubkey", "", "Path to an RSA public key PEM. When present, an encrypted manifest.tar is added to the backup set.")

	if err := flags.Parse(args); err != nil {
		return err
	}

	if flags.NArg() < 2 {
		flags.Usage()
		fmt.Println(`Source and output dirs must be specified.`)
		os.Exit(1)
	}

	inPath, err := filepath.Abs(flags.Arg(0))
	if err != nil {
		return err
	}

	if !filepath.IsAbs(*keycache) {
		*keycache = filepath.Clean(filepath.Join(inPath, *keycache))
	}

	outPath, err := filepath.Abs(flags.Arg(1))
	if err != nil {
		return err
	}
	os.MkdirAll(outPath, 0755)

	// TODO: Read secrets from a configuration file
	scanner := Scanner{
		Secrets: make(map[string]string),
	}

	// Scan to get os.FileInfo and the Convergence Secret for the new file set.
	results, err := scanner.Scan(inPath)
	if err != nil {
		return err
	}

	// Load the manifest from disk
	var manifest Manifest
	manifestFile, err := os.Open(*keycache)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	defer manifestFile.Close()

	if err == nil {
		if err := manifest.Load(manifestFile); err != nil {
			return err
		}
	} else {
		manifest.Init()
	}

	// Match the scanned results to entries in the file
	entries, err := manifest.Resolve(inPath, results)
	if err != nil {
		panic(err)
	}

	// Get prospective changeset containing items to update or delete
	diff := manifest.Diff(inPath, entries)

	if diff.IsEmpty() {
		fmt.Println("No changes detected.")
		os.Exit(0)
	}

	// Create a channel to send ManifestEntry structs to a worker pool
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
		// func(ManifestEntry) returns error or nil
		entry, isEntry := i.(ManifestEntry)
		if !isEntry {
			return fmt.Errorf("Unrecognized Input: %v", i)
		}
		filename := entry.HMAC.URLChars(filenameLen)

		fmt.Printf("Updating %s (%s)\n", filename, entry.Path)

		// Check if the file needs to be backed up, looking for its unique filename in outPath.
		outFilePath := filepath.Join(outPath, filename)

		if _, err := os.Stat(outFilePath); os.IsNotExist(err) {
			// Encrypt files that don't exist in the output directory
			sourceFile, err := os.Open(filepath.Join(inPath, entry.Path))
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
		logFatal("Errors occurred, not updating manifest.")
	}

	// The 'Remove' part of the diff is not yet actionable; We must commit first, then filter for garbage.
	manifest.Commit(diff)
	if err := manifest.Save(*keycache); err != nil {
		logFatal("Could not update Manifest file: %v", err)
	}

	if *pubkey != "" {
		// Encrypt manifest with a fully random key, and write a copy of that key
		// to a corresponding file with RSA OAEP asymmetric encryption.
		// Only the private key holder may decrypt the random key used to access the manifest.

		// TODO: Provide options for the manifest and/or its keyfile to be placed in arbitrary location(s).

		// Load the public key from the given file. Key must be at least minRSAKeySize.
		rsaPubkey, err := LoadPublicKey(*pubkey)
		if err != nil {
			logFatal(err.Error())
		}

		// Read from crypto/rand.Reader to create a random symmetric key.
		randomKey := make([]byte, blobcrypt.KeySize)
		if n, err := rand.Reader.Read(randomKey); n != blobcrypt.KeySize {
			return fmt.Errorf("Could not read enough random bytes for key")
		} else if err != nil {
			return err
		}

		// Encrypt the key so that it can be safely added alongside the content.
		encipheredKey, err := EncryptKey(randomKey, rsaPubkey)
		if err != nil {
			return err
		}

		// Create and open the destination file
		dstPath := filepath.Join(outPath, encryptedManifestName)
		outFile, err := os.Create(dstPath)
		if err != nil {
			return err
		}

		tarWriter := tar.NewWriter(outFile)

		sourceFile, err := os.Open(*keycache)
		if err != nil {
			return err
		}

		sourceInfo, err := sourceFile.Stat()
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(sourceInfo, "")
		header.Name = "manifest.json"
		// Size of sourceFile will be increased by exactly HMACSize when writing
		header.Size += blobcrypt.HMACSize
		header.PAXRecords = map[string]string{
			// key contains the asymmetrically-encrypted key for the body bytes.
			// There's no utility in making this a file record since openssl can't decrypt OAEP anyway.
			"BLOBCRYPT.key":      base64.RawStdEncoding.EncodeToString(encipheredKey),
			"BLOBCRYPT.key.type": "oaep-aes256",
		}

		tarWriter.WriteHeader(header)

		writer := blobcrypt.Writer{
			Source: sourceFile,
			Key:    randomKey,
		}

		// TODO: Write output files atomically
		_, err = writer.Encrypt(tarWriter)
		if err != nil {
			return err
		}

		if err := tarWriter.Close(); err != nil {
			return err
		}
	}

	// Now that manifest is current, get a list of all HMACs that are still valid.
	// Remember that files may exist in the backup set that are not part of the current directory.
	for _, entry := range manifest.GarbageCollectable(diff.Remove) {
		outFilePath := filepath.Join(outPath, entry.HMAC.URLChars(filenameLen))
		_ = os.Remove(outFilePath)
		fmt.Printf("Removed %s (%s)\n", entry.HMAC.URLChars(filenameLen), entry.Path)
	}

	return nil
}
