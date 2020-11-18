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

// Manifest defines a file that persists state across backups.
// Manifest files should never be backed up to a public location.
type Manifest struct {
	Header  struct{} // For future use
	Entries map[LocalHash]ManifestEntry
	mutex   sync.Mutex
}

// ManifestEntry holds change-detection and encryption info for a file.
type ManifestEntry struct {
	LocalHash LocalHash
	Path      string
	Key       []byte
	HMAC      HMAC512
}

// ManifestDiff describes a set of prospective changes to a Manifest.
type ManifestDiff struct {
	Change []ManifestEntry
	Remove []ManifestEntry
}

// IsEmpty returns true when ManifestDiff contains no actionable changes.
func (d *ManifestDiff) IsEmpty() bool {
	return len(d.Change) == 0 && len(d.Remove) == 0
}

// Diff replaces all entries under the given path with the given entries.
// Returns a ManifestDiff containing updated and removed entries under path.
// If an entry has the same LocalHash as an entry in the cache, it is not included in the diff.
// After changes are processed, the diff may be passed to Commit to modify Manifest.
func (k *Manifest) Diff(path string, entries []ManifestEntry) ManifestDiff {
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

	var diff ManifestDiff
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

// Commit updates the Manifest's Entries to reflect a set of changes that have been processed.
func (k *Manifest) Commit(diff ManifestDiff) {
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
func (k *Manifest) GarbageCollectable(entries []ManifestEntry) []ManifestEntry {
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
	var result []ManifestEntry
	for _, entry := range entries {
		if _, ok := collectable[entry.HMAC]; ok {
			result = append(result, entry)
		}
	}
	return result
}

// Init initializes a Manifest to the empty state
func (k *Manifest) Init() {
	k.Header = struct{}{}
	k.Entries = make(map[LocalHash]ManifestEntry)
}

// Load loads the contents of Manifest from the file at the given path
func (k *Manifest) Load(r io.Reader) error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	entries := make(map[LocalHash]ManifestEntry)

	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&k.Header); err != nil {
		return err
	}
	for {
		var entry ManifestEntry
		if err := decoder.Decode(&entry); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		entries[entry.LocalHash] = entry
	}

	// Replace k.Entries with the new set
	k.Entries = entries

	return nil
}

// Save writes the Manifest to a file at the given path
func (k *Manifest) Save(path string) error {
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
func (k *Manifest) GetEntry(localHash LocalHash) (ManifestEntry, bool) {
	k.mutex.Lock()
	defer k.mutex.Unlock()
	entry, ok := k.Entries[localHash]
	return entry, ok
}

// FindEntryWithHMAC searches the receiver for an entry corresponding to hmac
// If an entry is found, a copy of the entry is returned, otherwise nil.
func (k *Manifest) FindEntryWithHMAC(hmac HMAC512) *ManifestEntry {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	for _, entry := range k.Entries {
		if entry.HMAC == hmac {
			return &entry
		}
	}
	return nil
}

// Resolve converts a slice of ScanResults into ManifestEntries matched against the Manifest.
// If a file is not already present in the cache, or may have changed, it is
// read in its entirety on a worker pool to produce its Key and HMAC.
// This method does not write encrypted files to disk.
func (k *Manifest) Resolve(results []ScanResult) ([]ManifestEntry, error) {
	// Create a channel and start sending all ScanResults into it.
	c := make(chan interface{})
	go func() {
		defer close(c)
		for _, result := range results {
			c <- result
		}
	}()

	workerResults := RunWorkers(0, c, func(i interface{}) interface{} {
		// func(ScanResult) returns ManifestEntry or error
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

		return ManifestEntry{
			Path:      result.Path,
			Key:       key,
			HMAC:      hmacFixed,
			LocalHash: localHash,
		}
	})

	entries := make([]ManifestEntry, 0, len(results))
	for _, wResult := range workerResults {
		switch obj := wResult.(type) {
		case ManifestEntry:
			entries = append(entries, obj)
		case error:
			return nil, obj
		}
	}

	return entries, nil
}
