package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Scanner scans a directory, associating each file with its correct Convergence Secret
type Scanner struct {
	Secrets map[string]string // A map of Convergence Secrets by root path.
}

// ScanResult contains info about a file on the filesystem and its Convergence Secret, plus any error encountered
type ScanResult struct {
	Path  string
	Info  os.FileInfo
	Error error  // An error returned by filepath.Walk, if any.
	CS    string // Convergence Secret
}

// Scan scans all files in the current filesystem at the absolute path given by dir.
// Returns an array of ScanResult with convergence secrets set.
func (s *Scanner) Scan(dir string) ([]ScanResult, error) {
	// Collect the list of subpaths of dir, which have defined Secrets.
	var pathsWithSecrets []string
	for key := range s.Secrets {
		if strings.HasPrefix(key, dir) {
			pathsWithSecrets = append(pathsWithSecrets, key)
		}
	}
	// Sort all the matching keys in descending order.
	// This causes subdirectories to appear before their parents.
	sort.SliceStable(pathsWithSecrets, func(i, j int) bool {
		return pathsWithSecrets[i] > pathsWithSecrets[j]
	})

	// Lookup table to check if there is a different convergence secret for any subpath of key
	hasSubpathSecrets := make(map[string]bool)
	// Ensure we have a sane value for the root, when no root key is provided.
	hasSubpathSecrets["/"] = len(pathsWithSecrets) > 0
	var prevKey string
	for _, key := range pathsWithSecrets {
		// If a subdirectory precedes this entry in the list, we will have to check for
		hasSubpathSecrets[key] = strings.HasPrefix(prevKey, key)
	}

	// Walk files.
	keyDir := "\x00" // Start with an impossible value to trigger initialization
	checkSubpaths := true
	var convergenceSecret string
	var allResults []ScanResult

	err := filepath.Walk(dir, func(path string, info os.FileInfo, errIn error) error {
		if strings.HasPrefix(filepath.Base(path), ".") {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		result := ScanResult{
			Path:  path,
			Info:  info,
			Error: errIn,
		}

		if info != nil && info.IsDir() {
			if errIn != nil {
				// Skip directories that encounter errors
				return filepath.SkipDir
			}
		} else if errIn != nil {
			// Ignore files that encounter errors
			allResults = append(allResults, result)
			return nil
		}

		if !strings.HasPrefix(path, keyDir) {
			// Ascending out of the directory for current convergence secret.
			// Find the best convergence secret for this value.
			pDir := path
			for ; pDir > "/"; pDir = filepath.Dir(pDir) {
				if secret, ok := s.Secrets[pDir]; ok {
					keyDir = pDir
					convergenceSecret = secret
					break
				}
			}
			// If no path exists, use the root secret (or empty string if not defined).
			if pDir == "/" {
				keyDir = "/"
				convergenceSecret = s.Secrets[keyDir]
			}
			checkSubpaths = hasSubpathSecrets[keyDir]
		} else if checkSubpaths {
			if secret, ok := s.Secrets[path]; ok {
				if info.IsDir() {
					// Descending into a directory with a new secret.
					keyDir = path
					convergenceSecret = secret
				} else {
					// For individual file secrets, return early and don't mutate iteration state
					result.CS = secret
					allResults = append(allResults, result)
					return nil
				}
			}
		}

		if !info.IsDir() {
			result.CS = convergenceSecret
			allResults = append(allResults, result)
		}

		return nil
	})

	return allResults, err
}

// LocalHash returns a hash built from local metadata state, or an error if one occurred.
// This method is conservative and could produce different modification codes for unchanged files.
func (r *ScanResult) LocalHash() ([]byte, error) {
	if r.Error != nil {
		return nil, fmt.Errorf("Invalid ScanInfo: %w", r.Error)
	}

	info := r.Info
	if info == nil {
		return nil, fmt.Errorf("ScanResult is uninitialized")
	}

	modTimeBytes, err := info.ModTime().MarshalBinary()
	if err != nil {
		return nil, err
	}
	size := info.Size()
	var sizeBytes = make([]byte, binary.Size(size))
	binary.PutVarint(sizeBytes, size)

	hash := sha256.New()
	// hash.Write never returns an error (per Docs)
	hash.Write([]byte(r.CS))
	hash.Write([]byte(r.Path))
	hash.Write(modTimeBytes)
	hash.Write(sizeBytes)

	hashed := hash.Sum(nil)
	return hashed[:], nil
}
