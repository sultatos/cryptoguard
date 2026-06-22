package crypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func mustKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func roundTrip(t *testing.T, dek, plaintext []byte) []byte {
	t.Helper()
	var enc bytes.Buffer
	if err := EncryptStream(dek, bytes.NewReader(plaintext), &enc); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	var dec bytes.Buffer
	if err := DecryptStream(dek, bytes.NewReader(enc.Bytes()), &dec); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", dec.Len(), len(plaintext))
	}
	return enc.Bytes()
}

func TestStreamRoundTrip(t *testing.T) {
	dek := mustKey(t)
	sizes := []int{
		0, 1, 1024,
		ChunkSize - 1, ChunkSize, ChunkSize + 1,
		2 * ChunkSize, 2*ChunkSize + 7,
		5*ChunkSize + 123,
	}
	for _, sz := range sizes {
		pt := make([]byte, sz)
		if _, err := rand.Read(pt); err != nil {
			t.Fatal(err)
		}
		roundTrip(t, dek, pt)
	}
}

func TestTamperDetected(t *testing.T) {
	dek := mustKey(t)
	pt := make([]byte, 3*ChunkSize+50)
	_, _ = rand.Read(pt)
	ct := roundTrip(t, dek, pt)

	// Flip a byte well past the header.
	tampered := append([]byte(nil), ct...)
	tampered[len(tampered)/2] ^= 0xFF

	err := DecryptStream(dek, bytes.NewReader(tampered), io.Discard)
	if err == nil {
		t.Fatal("expected authentication failure on tampered ciphertext")
	}
}

func TestTruncationDetected(t *testing.T) {
	dek := mustKey(t)
	pt := make([]byte, 3*ChunkSize) // exact multiple => multiple full chunks
	_, _ = rand.Read(pt)
	var enc bytes.Buffer
	if err := EncryptStream(dek, bytes.NewReader(pt), &enc); err != nil {
		t.Fatal(err)
	}
	// Drop the final chunk (ChunkSize + tag bytes).
	full := enc.Bytes()
	truncated := full[:len(full)-(ChunkSize+16)]

	err := DecryptStream(dek, bytes.NewReader(truncated), io.Discard)
	if err == nil {
		t.Fatal("expected failure on truncated stream")
	}
}

func TestExtensionDetected(t *testing.T) {
	dek := mustKey(t)
	pt := make([]byte, ChunkSize/2)
	_, _ = rand.Read(pt)
	var enc bytes.Buffer
	if err := EncryptStream(dek, bytes.NewReader(pt), &enc); err != nil {
		t.Fatal(err)
	}
	// Append a junk "extra chunk" after the real (final) one.
	extended := append(enc.Bytes(), make([]byte, ChunkSize+16)...)

	err := DecryptStream(dek, bytes.NewReader(extended), io.Discard)
	if err == nil {
		t.Fatal("expected failure on extended stream")
	}
}

func TestWrongKeyFails(t *testing.T) {
	dek := mustKey(t)
	other := mustKey(t)
	pt := make([]byte, ChunkSize+10)
	_, _ = rand.Read(pt)
	var enc bytes.Buffer
	if err := EncryptStream(dek, bytes.NewReader(pt), &enc); err != nil {
		t.Fatal(err)
	}
	if err := DecryptStream(other, bytes.NewReader(enc.Bytes()), io.Discard); err == nil {
		t.Fatal("expected failure decrypting with the wrong DEK")
	}
}

func TestDEKWrapRoundTrip(t *testing.T) {
	kek := mustKey(t)
	dek, err := NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := WrapDEK(kek, dek)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("plaintext DEK appears inside wrapped blob")
	}
	got, err := UnwrapDEK(kek, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("unwrapped DEK does not match original")
	}
}

func TestUnwrapWrongKEKFails(t *testing.T) {
	kek := mustKey(t)
	wrong := mustKey(t)
	dek, _ := NewDEK()
	wrapped, _ := WrapDEK(kek, dek)
	if _, err := UnwrapDEK(wrong, wrapped); err == nil {
		t.Fatal("expected failure unwrapping with wrong KEK")
	}
}

func TestKeySizeValidation(t *testing.T) {
	short := make([]byte, 16)
	if _, err := newAEAD(short); err == nil {
		t.Fatal("expected error for non-32-byte key")
	}
	var enc bytes.Buffer
	if err := EncryptStream(short, bytes.NewReader([]byte("x")), &enc); err == nil {
		t.Fatal("expected EncryptStream to reject a short key")
	}
}
