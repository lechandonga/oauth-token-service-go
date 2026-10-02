package store

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// JSONFile persists a single JSON document to disk atomically. It is safe for
// concurrent use; callers that need the in-memory state and the on-disk state
// to stay consistent should hold their own lock across Load/Save sequences.
type JSONFile struct {
	path string
	mu   sync.Mutex
}

// NewJSONFile creates a persistence handle rooted at path.
func NewJSONFile(path string) *JSONFile {
	return &JSONFile{path: path}
}

// Path returns the backing file path.
func (f *JSONFile) Path() string { return f.path }

// Load reads the document into v. A missing file is not an error and leaves v
// untouched so callers can keep their zero value.
func (f *JSONFile) Load(v any) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	raw, err := os.ReadFile(f.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, v)
}

// Save writes v atomically (temp file + rename) with 0600 permissions.
func (f *JSONFile) Save(v any) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, f.path)
}
