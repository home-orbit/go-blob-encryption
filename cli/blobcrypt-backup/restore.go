package main

import (
	"archive/tar"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	blobcrypt "github.com/home-orbit/go-blob-encryption"
)

func restoreFile(inFile *os.File, entry *ManifestEntry, outPath string) error {
	// Decrypt the file to outPath
	os.MkdirAll(filepath.Dir(outPath), 0755)
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
	manifestPath := flags.String("manifest", encryptedManifestName, "Path to the backup manifest. If manifest is encrypted, privatekey is required. If this is a relative path, it is relative to SOURCE.")
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

	if !filepath.IsAbs(*manifestPath) {
		*manifestPath = filepath.Clean(filepath.Join(inPath, *manifestPath))
	}

	manifestFile, err := os.Open(*manifestPath)
	if err != nil {
		return fmt.Errorf("Cannot read %s", *manifestPath)
	}

	var manifest Manifest
	tarReader := tar.NewReader(manifestFile)
	header, err := tarReader.Next()
	if errors.Is(err, tar.ErrHeader) {
		// This is probably not a tar file after all. Try to read JSON.
		manifestFile.Seek(0, io.SeekStart)
		if err := manifest.Load(manifestFile); err != nil {
			return err
		}

	} else {
		for ; err == nil; header, err = tarReader.Next() {
			// Check to see if this entry is encrypted with our supported scheme.
			if keyString, keyOK := header.PAXRecords["BLOBCRYPT.key"]; keyOK {
				// Recover the raw bytes of the key, which may itself be encrypted.
				key, err := base64.RawStdEncoding.DecodeString(keyString)
				if err != nil {
					return err
				}

				keyType := header.PAXRecords["BLOBCRYPT.key.type"]
				switch keyType {
				case "oaep-aes256":
					if *privatekey == "" {
						return fmt.Errorf("Private Key is required to decrypt manifest")
					}
					// Loading the private key may prompt the user for their passphrase.
					priv, err := LoadPrivateKey(*privatekey)
					if err != nil {
						return err
					}
					fmt.Printf("Loaded %d-bit RSA Private Key\n", priv.Size()*8)

					// Decrypt the symmetric key used to encipher the main file.
					key, err = DecryptKey(key, priv)
					if err != nil {
						return err
					}
				default:
					return fmt.Errorf("Unrecognized Key Type: %s", keyType)
				}

				// IFF successful, bufferReader will contain the decrypted manifest.
				bufferReader, err := blobcrypt.DecryptAndCheckKey(tarReader, key)
				if err != nil {
					return err
				}
				if err := manifest.Load(bufferReader); err != nil {
					return err
				}
			} else {
				// Unencrypted file encountered in TAR
				if err := manifest.Load(tarReader); err != nil {
					return err
				}
			}
		}
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
			fileOut := filepath.Join(outPath, entry.Path)
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
