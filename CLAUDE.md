# CLAUDE.md

Guidance for AI coding agents (and humans) working in this repository.

CryptoGuard is a Go REST service for **streaming envelope encryption** of files
of any size. Read this before making changes — several invariants here are
security-critical and easy to break inadvertently.

## Commands

```bash
go mod tidy            # first run: fetch deps, generate go.sum
go test -race ./...    # unit tests (always run before claiming done)
go test -tags=integration ./...   # API round trip; needs Docker (testcontainers)
make generate          # regenerate sqlc code after editing queries.sql
make build             # build ./cmd/cryptoguard
make lint              # golangci-lint
make up / make down    # docker compose up --build / down -v
make key               # print a fresh base64 MASTER_KEY
```

Always `gofmt` (or `goimports`) edited files; CI assumes gofmt-clean.

## Architecture

Dependency direction is strict: `api → service → {crypto, storage, repository}`.

```
cmd/cryptoguard/      entrypoint, config wiring, graceful shutdown
internal/config/      env parsing + MASTER_KEY validation (fail-fast)
internal/crypto/      envelope (wrap/unwrap DEK) + chunked streaming AEAD
internal/storage/     filesystem blob store (atomic temp→fsync→rename)
internal/repository/  pgx pool + sqlc-backed metadata access
internal/service/     use cases; owns FS↔DB consistency ordering
internal/api/         handlers, stdlib mux router, middleware
migrations/           schema (also sqlc's schema source)
```

`internal/crypto` imports nothing from the rest of the tree. Keep it that way —
its testability depends on being pure.

## Invariants — do not break these

1. **Crypto stream format is load-bearing.** The on-disk layout is
   `magic("CGv1") || noncePrefix(7B) || chunk[0..N]`, each chunk AES-256-GCM with
   nonce = `prefix || counter(4B BE) || finalFlag(1B)`. Do **not** change nonce
   construction, chunk framing, magic, or `ChunkSize` casually: it changes
   security properties and breaks every already-encrypted file. Both encrypt and
   decrypt use one-chunk **read-ahead** to mark/verify the final chunk — this is
   what gives truncation/extension resistance. Preserve it.

2. **FS-before-DB ordering.** In `service.Encrypt`, the blob is written, fsynced,
   and atomically renamed **before** the metadata row is inserted; a failed
   insert removes the blob. Invariant: *a DB row exists ⇒ its blob exists*. Never
   reorder this so a row can exist without its file.

3. **`file_id` is parsed as a UUID before any filesystem use** (path-traversal
   guard). Never build a blob path from raw request input.

4. **MASTER_KEY fail-fast.** `config.Load` rejects a missing or non-32-byte key;
   the service must not start without a valid KEK. Don't add a fallback/default.

5. **Never log or persist plaintext keys** (KEK or DEKs), and never write secrets
   to the DB unencrypted. The DEK is only ever stored KEK-wrapped.

## Conventions

- **sqlc**: `internal/repository/db/` is generated. Do **not** hand-edit it — edit
  `internal/repository/queries.sql` (or the migration) and run `make generate`.
  The `uuid`/`timestamptz` overrides in `sqlc.yaml` keep models on plain
  `uuid.UUID`/`time.Time`; the google/uuid pgx codec is registered per-connection
  in `internal/repository/pool.go`.
- **Routing**: stdlib `net/http` with Go 1.22 method patterns
  (`mux.HandleFunc("POST /encrypt-file", ...)`, `r.PathValue("file_id")`). No
  third-party router. Middleware is the hand-rolled `Chain(...)` in
  `internal/api/middleware.go`.
- **Errors**: wrap with `%w` and a package prefix (e.g. `crypto: ...`). Map domain
  errors to HTTP status in the handler; never leak crypto error detail to clients.
- **Streaming**: use `io.Reader`/`io.Writer` end to end. Never read a whole file
  into memory — no `io.ReadAll` on request/file bodies, no
  `r.ParseMultipartForm` (use `r.MultipartReader()`).
- Repository methods translate to/from `db` types at the boundary; pgtype must not
  leak above `internal/repository`.

## Known constraints

- **Streaming download caveat**: once the decrypt response body starts, the 200 is
  committed; a mid-stream auth failure can only be logged, not turned into a 500.
  This is inherent and intentional — don't "fix" it by buffering the whole file.
- **Key zeroization**: Go's GC means key bytes can't be reliably wiped; the code
  doesn't pretend otherwise.

## Before finishing a change

- `go test -race ./...` passes (the crypto suite covers tamper/truncation/
  extension/wrong-key — keep it green).
- `gofmt`/`go vet` clean.
- If you touched queries or schema: `make generate` and commit the regenerated
  `db/` package.
- Update `AI_USAGE.md` if an AI assistant made non-trivial changes.
