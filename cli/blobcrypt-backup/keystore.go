package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"sync"

	blobcrypt "github.com/home-orbit/go-blob-encryption"
)

// Keystore defines a file that persists state across backups.
// Keystore files should never be backed up to a public location.
type Keystore struct {
	Header  struct{} // For future use
	Entries map[LocalHash]KeystoreEntry
	mutex   sync.Mutex
}

// KeystoreEntry holds change-detection and encryption info for a file.
type KeystoreEntry struct {
	LocalHash LocalHash
	Path      string
	Key       []byte
	HMAC      HMAC512
}

// KeystoreDiff describes a set of prospective changes to a Keystore.
type KeystoreDiff struct {
	Change []KeystoreEntry
	Remove []KeystoreEntry
}

// IsEmpty returns true when KeystoreDiff contains no actionable changes.
func (d *KeystoreDiff) IsEmpty() bool {
	return len(d.Change) == 0 && len(d.Remove) == 0
}

// Diff replaces all entries under the given path with the given entries.
// Returns a KeystoreDiff containing updated and removed entries under path.
// If an entry has the same LocalHash as an entry in the cache, it is not included in the diff.
// After changes are processed, the diff may be passed to Commit to modify Keystore.
func (k *Keystore) Diff(path string, entries []KeystoreEntry) KeystoreDiff {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	// Ensure path is always checked with a trailing slash
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	// Add the LocalHash for all incoming entries to a map
	inputMap := make(map[LocalHash]struct{}, len(entries))
	for idx := range entries {
		inputMap[entries[idx].LocalHash] = struct{}{}
	}

	var diff KeystoreDiff
	for localHash, entry := range k.Entries {
		if strings.HasPrefix(entry.Path, path) {
			if _, ok := inputMap[localHash]; ok {
				// Remove the entry from inputMap, to indicate an unchanged input entry.
				delete(inputMap, localHash)
				continue
			}
			// This entry is pending removal.
			// This doesn't mean the file was deleted, only that LocalHash is no longer current.
			diff.Remove = append(diff.Remove, entry)
		}
	}

	// Assign all the incoming entry values that have changed.
	for _, entry := range entries {
		if _, changed := inputMap[entry.LocalHash]; changed {
			diff.Change = append(diff.Change, entry)
		}
	}

	return diff
}

// Commit updates the Keystore's Entries to reflect a set of changes that have been processed.
func (k *Keystore) Commit(diff KeystoreDiff) {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	for _, entry := range diff.Change {
		k.Entries[entry.LocalHash] = entry
	}
	for _, entry := range diff.Remove {
		delete(k.Entries, entry.LocalHash)
	}
}

// GarbageCollectable returns the subset of entries whose HMACs no longer apppear in the list.
func (k *Keystore) GarbageCollectable(entries []KeystoreEntry) []KeystoreEntry {
	// Build a map of HMACs in the input list
	collectable := make(map[HMAC512]struct{}, len(entries))
	for idx := range entries {
		collectable[entries[idx].HMAC] = struct{}{}
	}

	// Remove all entries that are still held by another, remaining entry in k
	for _, entry := range k.Entries {
		delete(collectable, entry.HMAC)
	}

	// Filter input and return the subset that are no longer retained
	var result []KeystoreEntry
	for _, entry := range entries {
		if _, ok := collectable[entry.HMAC]; ok {
			result = append(result, entry)
		}
	}
	return result
}

// Load loads the contents of Keystore from the file at the given path
func (k *Keystore) Load(path string) error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	decoder := json.NewDecoder(f)
	if err := decoder.Decode(&k.Header); err != nil {
		return err
	}
	for {
		var entry KeystoreEntry
		if err := decoder.Decode(&entry); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		k.Entries[entry.LocalHash] = entry
	}

	return nil
}

// Save writes the Keystore to a file at the given path
func (k *Keystore) Save(path string) error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// TODO: Write file atomically
	encoder := json.NewEncoder(f)
	if err := encoder.Encode(k.Header); err != nil {
		return err
	}
	for _, entry := range k.Entries {
		if err := encoder.Encode(entry); err != nil {
			return err
		}
	}

	return nil
}

// GetEntry is a threadsafe accessor for Entries
func (k *Keystore) GetEntry(localHash LocalHash) (KeystoreEntry, bool) {
	k.mutex.Lock()
	defer k.mutex.Unlock()
	entry, ok := k.Entries[localHash]
	return entry, ok
}

// Resolve converts a slice of ScanResults into KeystoreEntries matched against the Keystore.
// If a file is not already present in the cache, or may have changed, it is
// read in its entirety on a worker pool to produce its Key and HMAC.
// This method does not write encrypted files to disk.
func (k *Keystore) Resolve(results []ScanResult) ([]KeystoreEntry, error) {
	// Create a channel and start sending all ScanResults into it.
	c := make(chan interface{})
	go func() {
		defer close(c)
		for _, result := range results {
			c <- result
		}
	}()

	workerResults := RunWorkers(0, c, func(i interface{}) interface{} {
		// func(ScanResult) returns KeystoreEntry or error
		result, isResult := i.(ScanResult)
		if !isResult {
			return fmt.Errorf("Unrecognized Input: %v", i)
		}

		var localHash LocalHash
		if err := localHash.Set(result.Path, result.CS, result.Info); err != nil {
			return fmt.Errorf("%w: %s", err, result.Path)
		}

		if entry, ok := k.GetEntry(localHash); ok {
			// No need to read the file, since LocalHash matches
			return entry
		}

		// Create a new entry for this file
		f, err := os.Open(result.Path)
		if err != nil {
			return fmt.Errorf("%w: %s", err, result.Path)
		}

		key, err := blobcrypt.ComputeKey(f, result.CS)
		if err != nil {
			return err
		}

		writer, err := blobcrypt.NewWriter(f, key)
		if err != nil {
			return err
		}

		hmac, err := writer.Encrypt(ioutil.Discard)
		if err != nil {
			return err
		}
		var hmacFixed HMAC512
		copy(hmacFixed[:], hmac)

		return KeystoreEntry{
			Path:      result.Path,
			Key:       key,
			HMAC:      hmacFixed,
			LocalHash: localHash,
		}
	})

	entries := make([]KeystoreEntry, 0, len(results))
	for _, wResult := range workerResults {
		switch obj := wResult.(type) {
		case KeystoreEntry:
			entries = append(entries, obj)
		case error:
			return nil, obj
		}
	}

	return entries, nil
}
