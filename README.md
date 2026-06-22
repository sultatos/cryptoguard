# CryptoGuard

A Go service exposing a RESTful API for **streaming file encryption** using the
**envelope encryption** pattern. Files of any size are encrypted and decrypted
as a stream — they are never fully loaded into memory.

---

## Envelope encryption in one paragraph

Encrypting everything under a single key is fragile: rotating that key means
re-encrypting all data, and one leak exposes everything. Envelope encryption
adds a layer. A long-lived **Key Encryption Key (KEK)** — the master key — only
ever encrypts other keys. Each file gets its own fresh, random **Data Encryption
Key (DEK)**. The file is encrypted with its DEK; the DEK is then encrypted
("wrapped") with the KEK and stored next to the file's metadata. To read a file
you unwrap its DEK with the KEK, then decrypt the file with the DEK.

This buys three things: a compromised DEK exposes only one file; rotating the KEK
means re-wrapping small DEKs, not rewriting large files; and the secrets are
split across stores — see below.
---

## How streaming AES-GCM works here

AES-GCM (via Go's `cipher.AEAD`) is all-or-nothing: it seals/opens a whole
message in memory and only verifies the auth tag over the entire input. That
conflicts with "don't read the whole file into memory."

CryptoGuard therefore splits the stream into **64 KiB chunks**, each sealed as an
independent AES-256-GCM message:

```
[ magic "CGv1" (4B) ][ nonce prefix (7B) ][ chunk_0 ][ chunk_1 ] ... [ chunk_N ]
```

Each chunk's 12-byte nonce is `prefix(7) || counter(4, big-endian) || final-flag(1)`:

- **Unique nonces** — every file has its own DEK *and* a random prefix, and the
  counter increments per chunk, so a (key, nonce) pair never repeats.
- **Truncation resistance** — the final chunk is sealed with the flag set; both
  encrypt and decrypt use one-chunk read-ahead, so dropping the real last chunk
  makes the new "last" chunk fail authentication.
- **Reordering resistance** — the counter is part of the nonce, so swapped chunks
  fail authentication.

Both directions stream with two chunk buffers at most; memory is flat regardless
of file size.
---
## Development

```bash
make test              # unit tests (incl. the crypto suite) with -race
make test-integration  # full HTTP round trip via testcontainers (needs Docker)
make generate          # regenerate sqlc code after editing queries.sql
make lint              # golangci-lint
make key               # print a fresh MASTER_KEY
```

**sqlc:** queries live in `internal/repository/queries.sql`; `sqlc generate`
writes the type-safe `internal/repository/db` package (committed). The
`uuid`/`timestamptz` overrides in `sqlc.yaml` keep generated models on plain
`uuid.UUID`/`time.Time`; the google/uuid pgx codec is registered per-connection
in `internal/repository/pool.go`.

---

## Project layout

```
internal/config/      env parsing + MASTER_KEY validation (fail-fast)
internal/crypto/      envelope (wrap/unwrap) + chunked streaming AEAD  ← pure, unit-tested
internal/storage/     filesystem blob store (atomic temp→fsync→rename)
internal/repository/  pgx pool + sqlc-backed metadata access
migrations/           schema (also sqlc's schema source)
```

Dependency direction: `api → service → {crypto, storage, repository}`. The crypto
package imports nothing from the rest, so its security properties are tested in
isolation.

---

## Design decisions & trade-offs

- **AES-256-GCM, chunked.** Required AEAD; chunking is the only safe way to stream
  it. A production system could instead use a vetted streaming AEAD (Google Tink,
  `filippo.io/age`); the framing here is implemented directly to make the
  mechanics explicit.
- **64 KiB chunks.** Balances per-chunk tag overhead (16 B) against memory and
  latency. Tunable.
- **Consistency.** Invariant: *a DB row exists ⇒ its blob exists*. The blob is
  written and `fsync`ed and atomically renamed before the row is inserted; a
  failed insert removes the blob. The only possible leak is an orphan blob with
  no row, which is safe to garbage-collect.
- **Path traversal.** `file_id` is parsed as a UUID before it is ever used to
  build a filesystem path.

---