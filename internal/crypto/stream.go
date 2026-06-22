package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// On-disk stream format:
//
//	[ magic("CGv1", 4B) ][ noncePrefix(7B) ][ chunk_0 ][ chunk_1 ] ... [ chunk_N ]
//
// Each chunk is AES-256-GCM(plaintext_segment) and is at most ChunkSize+tag bytes.
// Every file gets a unique DEK *and* a random nonce prefix, so nonces never repeat.
//
// Per-chunk nonce (12 bytes) = noncePrefix(7) || counter(4, big-endian) || lastFlag(1).
// The counter binds chunk ordering; the lastFlag binds finality. Together they make
// the stream resistant to truncation, extension, and reordering: a tampered stream
// changes which (nonce, ciphertext) pairs the decryptor expects, so GCM auth fails.
const (
	// ChunkSize is the plaintext segment size. 64 KiB balances per-chunk tag
	// overhead (16 B) against memory use and streaming granularity.
	ChunkSize      = 64 * 1024
	noncePrefixLen = 7
	nonceLen       = 12 // must equal aead.NonceSize() for AES-GCM
	counterLen     = 4
)

var magic = []byte("CGv1")

// makeNonce composes the 12-byte per-chunk nonce.
func makeNonce(prefix []byte, counter uint32, last bool) []byte {
	nonce := make([]byte, nonceLen)
	copy(nonce[:noncePrefixLen], prefix)
	binary.BigEndian.PutUint32(nonce[noncePrefixLen:noncePrefixLen+counterLen], counter)
	if last {
		nonce[nonceLen-1] = 1
	}
	return nonce
}

// readChunk fills buf as far as possible. It returns (n, nil) for a full or a
// short-but-nonempty read, and (0, io.EOF) once the reader is fully drained.
func readChunk(r io.Reader, buf []byte) (int, error) {
	n, err := io.ReadFull(r, buf)
	switch {
	case err == nil:
		return n, nil
	case errors.Is(err, io.ErrUnexpectedEOF):
		return n, nil // partial final chunk — still valid data
	case errors.Is(err, io.EOF):
		return 0, io.EOF // clean end, no data
	default:
		return n, err
	}
}

// EncryptStream reads plaintext from src and writes the encrypted stream to dst.
// It never buffers more than two chunks at a time, so file size is irrelevant.
//
// It uses one-chunk read-ahead so it can mark the final chunk's nonce, which is
// what lets DecryptStream detect truncation. An empty input still emits exactly
// one (empty) final chunk so it round-trips correctly.
func EncryptStream(dek []byte, src io.Reader, dst io.Writer) error {
	aead, err := newAEAD(dek)
	if err != nil {
		return err
	}
	prefix := make([]byte, noncePrefixLen)
	if _, err := rand.Read(prefix); err != nil {
		return fmt.Errorf("crypto: generate nonce prefix: %w", err)
	}
	if _, err := dst.Write(magic); err != nil {
		return err
	}
	if _, err := dst.Write(prefix); err != nil {
		return err
	}

	buf := make([]byte, ChunkSize)
	next := make([]byte, ChunkSize)
	out := make([]byte, 0, ChunkSize+aead.Overhead())

	n, err := readChunk(src, buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}

	var counter uint32
	for {
		nn, nerr := readChunk(src, next)
		if nerr != nil && !errors.Is(nerr, io.EOF) {
			return nerr
		}
		last := errors.Is(nerr, io.EOF) // no more data after the current chunk

		nonce := makeNonce(prefix, counter, last)
		out = aead.Seal(out[:0], nonce, buf[:n], nil)
		if _, werr := dst.Write(out); werr != nil {
			return werr
		}
		if last {
			return nil
		}

		buf, next = next, buf
		n = nn
		counter++
		if counter == 0 {
			return errors.New("crypto: chunk counter overflow")
		}
	}
}

// DecryptStream reverses EncryptStream. It verifies every chunk's authentication
// tag before writing its plaintext, and rejects any stream whose final chunk is
// not marked final (truncation) or has trailing data (extension).
func DecryptStream(dek []byte, src io.Reader, dst io.Writer) error {
	aead, err := newAEAD(dek)
	if err != nil {
		return err
	}

	header := make([]byte, len(magic)+noncePrefixLen)
	if _, err := io.ReadFull(src, header); err != nil {
		return fmt.Errorf("crypto: read stream header: %w", err)
	}
	if !bytes.Equal(header[:len(magic)], magic) {
		return errors.New("crypto: bad magic — not a CryptoGuard stream")
	}
	prefix := header[len(magic):]

	maxChunk := ChunkSize + aead.Overhead()
	buf := make([]byte, maxChunk)
	next := make([]byte, maxChunk)
	plain := make([]byte, 0, ChunkSize)

	n, err := readChunk(src, buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if errors.Is(err, io.EOF) {
		return errors.New("crypto: truncated stream — no chunks present")
	}

	var counter uint32
	for {
		nn, nerr := readChunk(src, next)
		if nerr != nil && !errors.Is(nerr, io.EOF) {
			return nerr
		}
		last := errors.Is(nerr, io.EOF)

		nonce := makeNonce(prefix, counter, last)
		plain, err = aead.Open(plain[:0], nonce, buf[:n], nil)
		if err != nil {
			return fmt.Errorf("crypto: chunk %d failed authentication: %w", counter, err)
		}
		if _, werr := dst.Write(plain); werr != nil {
			return werr
		}
		if last {
			return nil
		}

		buf, next = next, buf
		n = nn
		counter++
		if counter == 0 {
			return errors.New("crypto: chunk counter overflow")
		}
	}
}
