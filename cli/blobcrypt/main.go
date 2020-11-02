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

	out, err := os.Create(outfile)
	if err != nil {
		return err
	}
	defer out.Close()

	return reader.Decrypt(out)
}

func main() {
	// Parse command-line arguments. By default, encrypt the file at arg[0]
	flags := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flags.Usage = func() {
		basename := filepath.Base(os.Args[0])
		fmt.Println(`Usage: ` + basename + ` [-encrypt|-decrypt] [-keyfile KEYFILE] INFILE OUTFILE`)
		fmt.Println(`  Only single files may be specified.`)
		fmt.Println(`  If OUTFILE is a directory, the basename of INFILE is appended.`)
		fmt.Println(`  When encrypting, keyfile is written to OUTFILE + ".key" by default`)
		fmt.Println(`  When decrypting, keyfile is read from INFILE + ".key" by default`)
		fmt.Println(`  To override this behavior, specify -keyfile`)
		flags.PrintDefaults()
	}
	encrypt := flags.Bool("encrypt", false, "Encrypt the input file to output.")
	decrypt := flags.Bool("decrypt", false, "Decrypt the input file to output.")
	keyfile := flags.String("keyfile", "", "File to read or write key.")
	keyliteral := flags.String("key", "", "The decryption key. If specified, keyfile is ignored.")

	flags.Parse(os.Args[1:])

	if flags.NArg() < 2 {
		flags.Usage()
		fmt.Println(`Source and Destination files must be specified. Pass "-" to use stdin / stdout`)
		os.Exit(1)
	}
	inPath := flags.Arg(0)
	outPath := flags.Arg(1)
	if stat, err := os.Stat(outPath); err == nil {
		if stat.IsDir() {
			inBase := filepath.Base(inPath)
			outPath = filepath.Join(outPath, inBase)
		}
	}

	if *encrypt && *decrypt {
		log.Fatal("Cannot specify both -encrypt and -decrypt")
	}
	if !(*encrypt || *decrypt) {
		*encrypt = true
	}

	if *encrypt {
		if *keyfile == "" {
			*keyfile = outPath + ".key"
		}
		fmt.Printf("Encoding: %s -> %s / %s\n", inPath, outPath, *keyfile)
		if err := blobcrypt.EncryptFile(inPath, outPath, *keyfile); err != nil {
			panic(err)
		}
	} else {
		if *keyfile == "" {
			*keyfile = inPath + ".key"
		}
		if *keyliteral == "" {
			keyBytes, err := ioutil.ReadFile(*keyfile)
			if err != nil {
				fmt.Printf("Error opening key file: %v\n", err)
				os.Exit(1)
			}
			*keyliteral = strings.TrimSpace(string(keyBytes))
		}
		fmt.Printf("Decoding: %s -> %s\n", inPath, outPath)
		if err := decryptFile(inPath, outPath, *keyliteral); err != nil {
			panic(err)
		}
	}
}
