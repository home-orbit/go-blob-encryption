package main

import (
	"crypto/hmac"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

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
	// Filenames use 38 base64 chars for ~228 bits of collision resistance
	filenameLen = 38
)

func main() {
	// Parse command-line arguments. By default, encrypt the file at arg[0]
	flags := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	userHomeDir, _ := os.UserHomeDir()
	keyfile := flags.String("keyfile", filepath.Join(userHomeDir, defaultKeystoreName), "Path to the keystore file.")

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

	// TODO: Read secrets from a file rather than recreating each time
	secrets := make(map[string]string)
	{
		private := filepath.Join(inPath, "private/")
		// Dummy uuid for testing
		secrets[private] = "10D9879E-D074-4F51-ADE7-6944E6733691"
	}

	scanner := Scanner{
		Secrets: secrets,
	}

	// Scan to get os.FileInfo and the Convergence Secret for the new file set.
	results, err := scanner.Scan(inPath)
	if err != nil {
		panic(err)
	}

	// Load the keystore from disk
	keystore := Keystore{
		Entries: make(map[string]KeystoreEntry),
	}
	keystore.Load(*keyfile)

	// Match the scanned results to entries in the file
	entries, err := keystore.Resolve(results)
	if err != nil {
		panic(err)
	}

	// Get prospective changeset containing items to update or delete
	diff := keystore.Diff(inPath, entries)

	// Create a channel to supply updates to a worker pool
	updateInput := make(chan KeystoreEntry, 10)
	var group sync.WaitGroup

	changeCount := len(diff.Change)
	group.Add(changeCount)
	if changeCount > 0 {
		for i := 0; i < runtime.NumCPU(); i++ {
			go func() {
				for entry := range updateInput {
					// Check if the file needs to be backed up, looking for its unique filename in outPath.
					outFilePath := filepath.Join(outPath, entry.HMAC.URLChars(filenameLen))

					if _, err := os.Stat(outFilePath); os.IsNotExist(err) {
						// Encrypt files that don't exist in the output directory
						sourceFile, err := os.Open(entry.Path)
						if err != nil {
							panic(err)
						}

						outFile, err := os.Create(outFilePath)
						if err != nil {
							panic(err)
						}

						writer := blobcrypt.Writer{
							Source: sourceFile,
							Key:    entry.Key,
						}

						// TODO: Write output files atomically
						outputHMAC, err := writer.Encrypt(outFile)
						if !hmac.Equal(entry.HMAC[:], outputHMAC) {
							panic(err)
						}
					}
					// Exit the change group once for each file
					group.Done()
				}
			}()
		}
	}

	for _, updated := range diff.Change {
		fmt.Printf("Updating %s (%s)\n", updated.HMAC.URLChars(filenameLen), updated.Path)
		updateInput <- updated
	}
	// TODO: Handle errors from parallel processing (instead of panicking)
	group.Wait()

	// The 'Remove' part of the diff is not yet actionable; We must commit first, then filter for garbage.

	keystore.Commit(diff)
	defer keystore.Save(*keyfile)

	// Now that keystore is current, get a list of all HMACs that are still valid.
	// Remember that files may exist in the backup set that are not part of the current directory.
	for _, entry := range keystore.GarbageCollectable(diff.Remove) {
		outFilePath := filepath.Join(outPath, entry.HMAC.URLChars(filenameLen))
		_ = os.Remove(outFilePath)
		fmt.Printf("Removed %s (%s)\n", entry.HMAC.URLChars(filenameLen), entry.Path)
	}
}