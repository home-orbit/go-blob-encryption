package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	blobcrypt "github.com/home-orbit/go-blob-encryption"
)

func restoreFile(inFile *os.File, entry *ManifestEntry, outPath string) error {
	// Decrypt the file to outPath
	destFile, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer destFile.Close()

	fileReader, err := blobcrypt.NewReader(inFile, entry.Key)
	if err != nil {
		return err
	}

	return fileReader.Decrypt(destFile)
}

// RestoreMain is the main function when the first CLI argument is "backup" or is omitted.
func RestoreMain(args []string) error {
	// Parse command-line arguments. By default, encrypt the file at arg[0]
	flags := flag.NewFlagSet("restore", flag.ContinueOnError)
	manifestPath := flags.String("manifest", "", "Path to the backup manifest. If manifest is encrypted, keyfile is required.")
	keyfile := flags.String("keyfile", "", "Path to a file containing the manifest's decryption key. If key is encrypted, privatekey is required.")
	privatekey := flags.String("privatekey", "", "Path to an RSA private key PEM. Used to decrypt the manifest's keyfile.")

	flags.Usage = func() {
		fmt.Println("Usage of restore [opts] SOURCE DEST:")
		flags.PrintDefaults()
		fmt.Println()
		fmt.Println(`  When SOURCE and DEST are both directories, all files in manifest with an encrypted file in SOURCE are decrypted to DEST`)
	}

	if err := flags.Parse(args); err != nil {
		return err
	}

	if flags.NArg() < 2 {
		flags.Usage()
		fmt.Println(`Source and output dirs must be specified.`)
		os.Exit(1)
	}

	if *manifestPath == "" {
		logFatal("-manifest is required to restore files")
	}
	manifestFile, err := os.Open(*manifestPath)
	if err != nil {
		logFatal("Cannot read %s", *manifestPath)
	}

	var manifest Manifest
	if *keyfile != "" {
		symmetricKey, err := ioutil.ReadFile(*keyfile)
		if err != nil {
			return err
		}

		// If a private key is present, recover the symmetric key.
		// This may prompt the user for their password.
		if *privatekey != "" {
			priv, err := LoadPrivateKey(*privatekey)
			if err != nil {
				return err
			}
			fmt.Printf("Loaded %d-bit RSA Private Key\n", priv.Size()*8)
			symmetricKey, err = DecryptKey(symmetricKey, priv)
			if err != nil {
				return err
			}
		}

		// At this point, symmetric key should be ready for use.
		reader, err := blobcrypt.NewReader(manifestFile, symmetricKey)
		if err != nil {
			return err
		}
		// Decrypt the manifest into a buffer. It must fit in memory.
		var buffer bytes.Buffer
		err = reader.Decrypt(&buffer)
		if err != nil {
			return err
		}

		// Load te manifest from that data.
		err = manifest.Load(&buffer)
		if err != nil {
			return err
		}
	} else {
		// Try to read the file without encryption
		manifest.Load(manifestFile)
	}

	// Read inPath from the arguments list
	inPath, err := filepath.Abs(flags.Arg(0))
	if err != nil {
		return err
	}

	// Read outPath from the arguments list.
	// If this is a directory, it is not created in advance.
	outPath, err := filepath.Abs(flags.Arg(1))
	if err != nil {
		return err
	}

	inStat, err := os.Stat(inPath)
	if err != nil {
		return err
	}

	outStat, err := os.Stat(outPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	if inStat.IsDir() {
		// Decrypt all files from the manifest
		if !outStat.IsDir() {
			return fmt.Errorf("Output must be a directory when input is a directory")
		}

		manifest.mutex.Lock()
		defer manifest.mutex.Unlock()

		for _, entry := range manifest.Entries {
			fmt.Println(entry.Path, "...")
			inPath := filepath.Join(inPath, entry.HMAC.URLChars(filenameLen))
			inFile, err := os.Open(inPath)
			if os.IsNotExist(err) {
				fmt.Printf("Cannot find encrypted source for %s; Skipping\n", filepath.Base(entry.Path))
				continue
			} else if err != nil {
				return err
			}
			fileOut := filepath.Join(outPath, filepath.Base(entry.Path))
			err = restoreFile(inFile, &entry, fileOut)
			if err != nil {
				return err
			}
		}

	} else {
		// Need to find the key for this file's HMAC in the manifest
		inFile, err := os.Open(inPath)
		if err != nil {
			return err
		}

		_, err = inFile.Seek(-blobcrypt.HMACSize, io.SeekEnd)
		if err != nil {
			return err
		}

		var hmac HMAC512
		_, err = inFile.Read(hmac[:])
		if err != nil {
			return err
		}

		// Find the entry
		entry := manifest.FindEntryWithHMAC(hmac)
		if entry == nil {
			return fmt.Errorf("Manifest does not contain the decryption key for %s", inPath)
		}

		if outStat.IsDir() {
			// If outPath is a directory, add the input file's manifest basename.
			outPath = filepath.Join(outPath, filepath.Base(entry.Path))
		}

		return restoreFile(inFile, entry, outPath)
	}

	return nil
}
