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

/* This is a command-line interface to the blobcrypt library, which
 * encrypts and decrypts binary data for archival to public storage.
 * Files are encrypted with a key that is exactly the SHA256 hash
 * of the convergence secret and full source file.
 * Any software with the original file and convergence secret may generate
 * the encryption key and decrypt or verify the encrypted output.
 */

func encryptFile(infile, outfile, cs, keyfile string) ([]byte, error) {
	in, err := os.Open(infile)
	if err != nil {
		return nil, err
	}
	defer in.Close()

	key, err := blobcrypt.ComputeKey(in, cs)
	if err != nil {
		return nil, err
	}

	// Store the key first; If key can't be saved, there's no point in encrypting source.
	hexKey := hex.EncodeToString(key) + "\n"
	if err := ioutil.WriteFile(keyfile, []byte(hexKey), 0600); err != nil {
		return nil, err
	}

	// Create a Writer to encrypt the contents
	writer, err := blobcrypt.NewWriter(in, key)
	if err != nil {
		return nil, err
	}

	if outfile == "" {
		return writer.Encrypt(os.Stdout)
	}

	out, err := os.Create(outfile)
	if err != nil {
		return nil, err
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
		fmt.Println(`Usage: ` + basename + ` [-encrypt|-decrypt|-check] [-keyfile KEYFILE|-key "HEX"] [-cs "secret"] INPUT [OUTPUT]`)
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
	cs := flags.String("cs", "", "A Convergence Secret string. For small or sensitive files, a GUID is recommended")
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
		// TODO: Decide whether HMAC should be captured and/or displayed
		if _, err := encryptFile(inPath, outPath, *cs, *keyfile); err != nil {
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
