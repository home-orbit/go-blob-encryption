package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

/* This is a command-line interface to create and restore backups using convergent encryption.
 * This consists of a several phases:
 * - Scanning all the files in the source directory, matching them to convergence keys as needed
 * - Checking os.FileInfo for those files, to heuristically skip unchanged files
 * - Producing HMAC keys by reading the contents of files on the local filesystem
 * - Checking which HMAC keys are not present in the backup set
 * - Writing the encrypted contents of missing files to the backup set
 */

// TODO: Support recovering an encrypted index
//  blobcrypt-backup decrypt-index -privatekey .../private.pem [/path/to/index.key] /path/to/index DEST
// TODO: Support restoring files, given a valid index and source dir
//  blobcrypt-backup restore [-keyfile path/to/decrypted-index] DEST -- FILENAME GLOB GLOB

const (
	// keyCacheName is the default source-relative path to the cache of per-file keys.
	keyCacheName = ".blobcrypt-cache.json"
	// encryptedManifestName is the default name of an encrypted manifest TAR in the backup.
	encryptedManifestName = "manifest-encrypted.tar"
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
	// Must have at least one arg to choose a mode.
	flag.Usage = func() {
		fmt.Printf("Usage: %s backup|restore [opts] SOURCE DEST\n", filepath.Base(os.Args[0]))
		fmt.Println()
		BackupMain([]string{"-help"})
		fmt.Println()
		RestoreMain([]string{"-help"})
	}
	// flag.Parse exits on error by default
	flag.Parse()

	switch flag.Arg(0) {
	case "backup":
		if err := BackupMain(flag.Args()[1:]); err != nil {
			logFatal(err.Error())
		}
	case "restore":
		if err := RestoreMain(flag.Args()[1:]); err != nil {
			logFatal(err.Error())
		}
	default:
		logFatal("Unknown action: %s", flag.Arg(0))
	}
}
