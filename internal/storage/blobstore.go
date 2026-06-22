// Package storage persists encrypted file blobs on the local filesystem,
// addressed by file_id.
package storage

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

// BlobStore writes and reads encrypted blobs under a single directory.
type BlobStore struct {
	dir string
}

// New creates the storage directory if needed and returns a BlobStore.
func New(dir string) (*BlobStore, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("storage: create dir: %w", err)
	}
	return &BlobStore{dir: dir}, nil
}

// path is always built from a parsed UUID, never raw user input, so a request
// can never escape the storage directory via path traversal.
func (b *BlobStore) path(id uuid.UUID) string {
	return filepath.Join(b.dir, id.String())
}

// Write streams data (produced by write) into a temp file, fsyncs it, then
// atomically renames it to the canonical path. It returns only once the blob is
// durably in place, which lets the caller safely insert the DB row afterwards
// and preserve the invariant "a row exists => its blob exists".
func (b *BlobStore) Write(id uuid.UUID, write func(io.Writer) error) (err error) {
	tmp, err := os.CreateTemp(b.dir, id.String()+".*.tmp")
	if err != nil {
		return fmt.Errorf("storage: create temp: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if err = write(tmp); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("storage: fsync: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("storage: close temp: %w", err)
	}
	if err = os.Rename(tmpName, b.path(id)); err != nil {
		return fmt.Errorf("storage: rename: %w", err)
	}
	committed = true
	return nil
}

// Open returns a reader over the encrypted blob for id.
func (b *BlobStore) Open(id uuid.UUID) (io.ReadCloser, error) {
	f, err := os.Open(b.path(id))
	if err != nil {
		return nil, fmt.Errorf("storage: open blob: %w", err)
	}
	return f, nil
}

// Remove deletes a blob; used as the compensating action if a DB insert fails.
func (b *BlobStore) Remove(id uuid.UUID) error {
	return os.Remove(b.path(id))
}
