// Package repository is the data-access layer for file metadata. It wraps the
// sqlc-generated db package and maps between domain types and generated types.
package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"cryptoguard/internal/repository/db"
)

// ErrNotFound is returned when no row matches the requested file_id.
var ErrNotFound = errors.New("repository: file not found")

// FileMeta is the domain representation of a stored file's metadata.
type FileMeta struct {
	FileID           uuid.UUID
	OriginalFilename string
	EncryptedDEK     []byte
	SizeBytes        int64
}

// Repository provides metadata persistence over a pgx pool.
type Repository struct {
	pool    *pgxpool.Pool
	queries *db.Queries
}

// New returns a Repository backed by pool.
func New(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool, queries: db.New(pool)}
}

// CreateFile inserts a metadata row.
func (r *Repository) CreateFile(ctx context.Context, m FileMeta) error {
	_, err := r.queries.CreateFile(ctx, db.CreateFileParams{
		FileID:           m.FileID,
		OriginalFilename: m.OriginalFilename,
		EncryptedDek:     m.EncryptedDEK,
		SizeBytes:        m.SizeBytes,
	})
	if err != nil {
		return fmt.Errorf("repository: create file: %w", err)
	}
	return nil
}

// GetFile fetches a metadata row, translating "no rows" into ErrNotFound.
func (r *Repository) GetFile(ctx context.Context, id uuid.UUID) (FileMeta, error) {
	row, err := r.queries.GetFile(ctx, id)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return FileMeta{}, ErrNotFound
	case err != nil:
		return FileMeta{}, fmt.Errorf("repository: get file: %w", err)
	}
	return FileMeta{
		FileID:           row.FileID,
		OriginalFilename: row.OriginalFilename,
		EncryptedDEK:     row.EncryptedDek,
		SizeBytes:        row.SizeBytes,
	}, nil
}

// DeleteFile removes a metadata row (compensating action / cleanup).
func (r *Repository) DeleteFile(ctx context.Context, id uuid.UUID) error {
	if err := r.queries.DeleteFile(ctx, id); err != nil {
		return fmt.Errorf("repository: delete file: %w", err)
	}
	return nil
}
