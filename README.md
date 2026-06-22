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

### Where the secrets live

| Artifact | Location | On its own it is… |
|---|---|---|
| Encrypted file (DEK-encrypted) | local filesystem, named by `file_id` | useless without the DEK |
| Wrapped DEK + metadata | PostgreSQL | useless without the KEK |
| KEK (master key) | `MASTER_KEY` env var | never written to disk or DB |

An attacker needs the disk **and** the database **and** the environment to read anything.

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

## API

### `POST /encrypt-file`
`multipart/form-data` with a `file` field. Streams the upload straight into
chunked encryption.

```bash
curl -F "file=@report.pdf" http://localhost:8080/encrypt-file
# 201 Created
# {"file_id":"<uuid>","original_name":"report.pdf","size":123456}
```

### `GET /decrypt-file/{file_id}`
Streams the decrypted file back as an attachment.

```bash
curl -OJ http://localhost:8080/decrypt-file/<uuid>   # -OJ honours Content-Disposition
```

`GET /healthz` returns `200 ok`.

---

## Setup & running

> First time only: run `go mod tidy` to fetch dependencies and generate `go.sum`.

### With Docker Compose (recommended)

```bash
cp .env.example .env
echo "MASTER_KEY=$(openssl rand -base64 32)" >> .env   # or edit .env by hand
docker compose up --build
```

Compose starts Postgres (applying `migrations/0001_init.sql` on first init),
waits for its healthcheck, then starts the service on `:8080`.

### Locally

```bash
export MASTER_KEY=$(openssl rand -base64 32)
export DATABASE_URL='postgres://cryptoguard:cryptoguard@localhost:5432/cryptoguard?sslmode=disable'
make run
```

### Configuration

| Env var | Required | Default | Notes |
|---|---|---|---|
| `MASTER_KEY` | **yes** | — | base64 of exactly 32 bytes; service refuses to start otherwise |
| `DATABASE_URL` | no | local dev DSN | Postgres connection string |
| `STORAGE_DIR` | no | `./data/blobs` | where encrypted blobs are written |
| `LISTEN_ADDR` | no | `:8080` | HTTP listen address |

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
cmd/cryptoguard/      entrypoint, wiring, graceful shutdown
internal/config/      env parsing + MASTER_KEY validation (fail-fast)
internal/crypto/      envelope (wrap/unwrap) + chunked streaming AEAD  ← pure, unit-tested
internal/storage/     filesystem blob store (atomic temp→fsync→rename)
internal/repository/  pgx pool + sqlc-backed metadata access
internal/service/     use cases; owns the FS↔DB consistency ordering
internal/api/         handlers, router (stdlib mux), middleware
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
- **Streaming download caveat.** Once the response body starts, the `200` is
  committed; a mid-stream authentication failure can only be logged and the
  connection dropped — it cannot retroactively become a `500`. This is inherent
  to streaming an authenticated file.
- **Key zeroization.** Go's GC means key bytes can't be reliably wiped from
  memory; this implementation does not pretend otherwise.

---

## AI usage

See [`AI_USAGE.md`](./AI_USAGE.md).
