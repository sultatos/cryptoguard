// Package crypto implements envelope encryption: a per-file Data Encryption Key
// (DEK) encrypts the file contents, and the long-lived Key Encryption Key (KEK)
// encrypts ("wraps") each DEK. File contents are encrypted as a stream of
// independently-authenticated AES-256-GCM chunks so that arbitrarily large files
// never need to be held in memory.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

const (
	// KeySize is the AES-256 key length in bytes, used for both the KEK and DEKs.
	KeySize = 32
)

// newAEAD builds an AES-256-GCM AEAD from a 32-byte key. GCM's default nonce
// size is 12 bytes, which is what the streaming format below relies on.
func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("crypto: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// NewDEK returns a fresh, cryptographically-random 32-byte Data Encryption Key.
func NewDEK() ([]byte, error) {
	dek := make([]byte, KeySize)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("crypto: generate DEK: %w", err)
	}
	return dek, nil
}

// WrapDEK encrypts a DEK with the KEK using AES-256-GCM.
// The returned blob is: nonce || ciphertext || tag (safe to store in the DB).
func WrapDEK(kek, dek []byte) ([]byte, error) {
	aead, err := newAEAD(kek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: generate wrap nonce: %w", err)
	}
	// Seal appends the ciphertext to its first argument, so passing `nonce`
	// yields nonce||ciphertext||tag in one allocation.
	return aead.Seal(nonce, nonce, dek, nil), nil
}

// UnwrapDEK reverses WrapDEK, returning the plaintext DEK.
func UnwrapDEK(kek, wrapped []byte) ([]byte, error) {
	aead, err := newAEAD(kek)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(wrapped) < ns {
		return nil, errors.New("crypto: wrapped DEK too short")
	}
	nonce, ciphertext := wrapped[:ns], wrapped[ns:]
	dek, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: unwrap DEK: %w", err)
	}
	return dek, nil
}
