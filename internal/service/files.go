// Package service holds the application use cases: it ties the crypto, storage,
// and repository layers together and owns the consistency ordering between them.
package service

import (
	"context"
	"fmt"
	"io"

	"github.com/google/uuid"

	"cryptoguard/internal/crypto"
	"cryptoguard/internal/repository"
	"cryptoguard/internal/storage"
)

// ErrNotFound is re-exported so the API layer doesn't import the repository.
var ErrNotFound = repository.ErrNotFound

// FileService implements encrypt and decrypt.
type FileService struct {
	repo  *repository.Repository
	blobs *storage.BlobStore
	kek   []byte
}

// New wires the dependencies together.
func New(repo *repository.Repository, blobs *storage.BlobStore, kek []byte) *FileService {
	return &FileService{repo: repo, blobs: blobs, kek: kek}
}

// EncryptResult is returned to the API after a successful upload.
type EncryptResult struct {
	FileID       uuid.UUID
	OriginalName string
	Size         int64
}

// Encrypt performs streaming envelope encryption:
//  1. mint a fresh DEK and wrap it with the KEK,
//  2. stream-encrypt src to a durable blob on disk (temp -> fsync -> rename),
//  3. only then insert the metadata row; on insert failure, remove the blob.
//
// Ordering matters: the blob is durable before the row exists, so we never end
// up with a row that points at a missing file.
func (s *FileService) Encrypt(ctx context.Context, originalName string, src io.Reader) (EncryptResult, error) {
	dek, err := crypto.NewDEK()
	if err != nil {
		return EncryptResult{}, err
	}
	wrapped, err := crypto.WrapDEK(s.kek, dek)
	if err != nil {
		return EncryptResult{}, err
	}

	id := uuid.New()
	counter := &countingReader{r: src}

	if err := s.blobs.Write(id, func(w io.Writer) error {
		return crypto.EncryptStream(dek, counter, w)
	}); err != nil {
		return EncryptResult{}, fmt.Errorf("service: write blob: %w", err)
	}

	meta := repository.FileMeta{
		FileID:           id,
		OriginalFilename: originalName,
		EncryptedDEK:     wrapped,
		SizeBytes:        counter.n,
	}
	if err := s.repo.CreateFile(ctx, meta); err != nil {
		_ = s.blobs.Remove(id) // compensate: drop the orphaned blob
		return EncryptResult{}, err
	}

	return EncryptResult{FileID: id, OriginalName: originalName, Size: counter.n}, nil
}

// DecryptStreamer carries everything needed to stream one decrypted file. It is
// produced before any response body is written, so the handler can resolve
// not-found (and set headers) before committing to a 200.
type DecryptStreamer struct {
	OriginalName string
	dek          []byte
	blob         io.ReadCloser
}

// OpenForDecrypt loads metadata, unwraps the DEK, and opens the blob.
func (s *FileService) OpenForDecrypt(ctx context.Context, id uuid.UUID) (*DecryptStreamer, error) {
	meta, err := s.repo.GetFile(ctx, id)
	if err != nil {
		return nil, err // ErrNotFound bubbles up
	}
	dek, err := crypto.UnwrapDEK(s.kek, meta.EncryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("service: unwrap dek: %w", err)
	}
	blob, err := s.blobs.Open(id)
	if err != nil {
		// Row exists but blob is gone: a broken invariant, surfaced as an error.
		return nil, fmt.Errorf("service: open blob: %w", err)
	}
	return &DecryptStreamer{OriginalName: meta.OriginalFilename, dek: dek, blob: blob}, nil
}

// Stream streams the decrypted plaintext to w. Each chunk is authenticated
// before its bytes are written.
func (d *DecryptStreamer) Stream(w io.Writer) error {
	return crypto.DecryptStream(d.dek, d.blob, w)
}

// Close releases the underlying blob handle.
func (d *DecryptStreamer) Close() error {
	return d.blob.Close()
}

// countingReader counts plaintext bytes as they flow through, so we can record
// the original size without a separate stat.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
