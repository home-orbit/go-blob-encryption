package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	blobcrypt "github.com/home-orbit/go-blob-encryption"
)

/* This package contains library functions for encrypting
 * binary data for archival to public storage.
 * Files are encrypted with a key that is exactly the SHA3 hash
 * of the full source file, and any software with the SHA3 of
 * the original file may decrypt and verify the contents.
 */

func encryptFile(infile, outfile, keyfile string) error {
	in, err := os.Open(infile)
	if err != nil {
		return err
	}
	defer in.Close()

	key, err := blobcrypt.ComputeKey(in)
	if err != nil {
		return err
	}

	// Store the key first; If key can't be saved, there's no point in encrypting source.
	hexKey := hex.EncodeToString(key) + "\n"
	if err := ioutil.WriteFile(keyfile, []byte(hexKey), 0600); err != nil {
		return err
	}

	// Create a Writer to encrypt the contents
	writer, err := blobcrypt.NewWriter(in, key)
	if err != nil {
		return err
	}

	if outfile == "" {
		return writer.Encrypt(os.Stdout)
	}

	out, err := os.Create(outfile)
	if err != nil {
		return err
	}
	defer out.Close()

	return writer.Encrypt(out)
}

func decryptFile(infile, outfile, hashstr string) error {
	in, err := os.Open(infile)
	if err != nil {
		return err
	}
	defer in.Close()

	key, err := hex.DecodeString(hashstr)
	if err != nil {
		return err
	}

	reader, err := blobcrypt.NewReader(in, key)
	if err != nil {
		return err
	}

	if outfile == "" {
		return reader.Decrypt(os.Stdout)
	}

	out, err := os.Create(outfile)
	if err != nil {
		return err
	}
	defer out.Close()

	return reader.Decrypt(out)
}

func checkFile(infile, hashstr string) error {
	in, err := os.Open(infile)
	if err != nil {
		return err
	}
	defer in.Close()

	key, err := hex.DecodeString(hashstr)
	if err != nil {
		return err
	}

	_, err = blobcrypt.CheckKey(in, key)
	return err
}

func main() {
	// Parse command-line arguments. By default, encrypt the file at arg[0]
	flags := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flags.Usage = func() {
		basename := filepath.Base(os.Args[0])
		fmt.Println(`Usage: ` + basename + ` [-encrypt|-decrypt|-check] [-keyfile KEYFILE|-key "HEX"] INPUT [OUTPUT]`)
		fmt.Println(`  INPUT must be a regular file to encrypt or decrypt.`)
		fmt.Println(`  If OUTPUT is a directory, the basename of INFILE is appended.`)
		fmt.Println(`  If OUTPUT is not provided, stdout will be used.`)
		fmt.Println(``)
		flags.PrintDefaults()
	}
	encrypt := flags.Bool("encrypt", false, `Encrypt INPUT into OUTPUT. The default action.`)
	decrypt := flags.Bool("decrypt", false, `Decrypt INPUT to OUTPUT using key.`)
	check := flags.Bool("check", false, `Check that INPUT is valid and key is correct. No decryption occurs.`)
	keyliteral := flags.String("key", "", `The decryption key. If specified, keyfile is ignored.`)
	keyfile := flags.String("keyfile", "", `File to read or write key. Defaults to OUTPUT.key when encrypting, and INPUT.key when decrypting`)

	flags.Parse(os.Args[1:])

	if flags.NArg() < 1 {
		flags.Usage()
		fmt.Println(`Source and Destination files must be specified.`)
		os.Exit(1)
	}
	inPath := flags.Arg(0)
	outPath := flags.Arg(1)
	if outPath != "" {
		if stat, err := os.Stat(outPath); err == nil {
			if stat.IsDir() {
				inBase := filepath.Base(inPath)
				outPath = filepath.Join(outPath, inBase)
			}
		}
	}

	if (*encrypt && *decrypt) || (*encrypt && *check) || (*decrypt && *check) {
		log.Fatal("Only one of -encrypt, -decrypt, or -check may be specified")
	}
	if !(*encrypt || *decrypt || *check) {
		*encrypt = true
	}

	if *encrypt {
		if *keyfile == "" {
			*keyfile = outPath + ".key"
		}
		if err := encryptFile(inPath, outPath, *keyfile); err != nil {
			fmt.Fprintf(os.Stderr, "Encryption Failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		if *keyfile == "" {
			*keyfile = inPath + ".key"
		}
		if *keyliteral == "" {
			keyBytes, err := ioutil.ReadFile(*keyfile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error opening key file: %v\n", err)
				os.Exit(1)
			}
			*keyliteral = strings.TrimSpace(string(keyBytes))
		}

		if *decrypt {
			if err := decryptFile(inPath, outPath, *keyliteral); err != nil {
				fmt.Fprintf(os.Stderr, "Decryption Failed: %v\n", err)
				os.Exit(1)
			}
		} else if *check {
			if err := checkFile(inPath, *keyliteral); err != nil {
				fmt.Fprintf(os.Stderr, "Check Failed: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("OK")
		}
	}
}
