// Package config loads and validates runtime configuration from the environment.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"cryptoguard/internal/crypto"
)

// Config holds all runtime settings. MasterKey is the decoded 32-byte KEK.
type Config struct {
	MasterKey   []byte
	DatabaseURL string
	StorageDir  string
	ListenAddr  string
}

// Load reads configuration from the environment. It returns an error (so main
// can refuse to start) if MASTER_KEY is absent or not a base64-encoded 32 bytes.
func Load() (*Config, error) {
	raw := os.Getenv("MASTER_KEY")
	if raw == "" {
		return nil, errors.New("MASTER_KEY is required (base64-encoded 32 bytes)")
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("MASTER_KEY must be valid base64: %w", err)
	}
	if len(key) != crypto.KeySize {
		return nil, fmt.Errorf("MASTER_KEY must decode to %d bytes, got %d", crypto.KeySize, len(key))
	}

	return &Config{
		MasterKey:   key,
		DatabaseURL: getenv("DATABASE_URL", "postgres://cryptoguard:cryptoguard@localhost:5432/cryptoguard?sslmode=disable"),
		StorageDir:  getenv("STORAGE_DIR", "./data/blobs"),
		ListenAddr:  getenv("LISTEN_ADDR", ":8080"),
	}, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
