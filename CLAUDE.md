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

<!-- rtk-instructions v2 -->
# RTK (Rust Token Killer) - Token-Optimized Commands

## Golden Rule

**Always prefix commands with `rtk`**. If RTK has a dedicated filter, it uses it. If not, it passes through unchanged. This means RTK is always safe to use.

**Important**: Even in command chains with `&&`, use `rtk`:
```bash
# ❌ Wrong
git add . && git commit -m "msg" && git push

# ✅ Correct
rtk git add . && rtk git commit -m "msg" && rtk git push
```

## RTK Commands by Workflow

### Build & Compile (80-90% savings)
```bash
rtk cargo build         # Cargo build output
rtk cargo check         # Cargo check output
rtk cargo clippy        # Clippy warnings grouped by file (80%)
rtk tsc                 # TypeScript errors grouped by file/code (83%)
rtk lint                # ESLint/Biome violations grouped (84%)
rtk prettier --check    # Files needing format only (70%)
rtk next build          # Next.js build with route metrics (87%)
```

### Test (60-99% savings)
```bash
rtk cargo test          # Cargo test failures only (90%)
rtk go test             # Go test failures only (90%)
rtk jest                # Jest failures only (99.5%)
rtk vitest              # Vitest failures only (99.5%)
rtk playwright test     # Playwright failures only (94%)
rtk pytest              # Python test failures only (90%)
rtk rake test           # Ruby test failures only (90%)
rtk rspec               # RSpec test failures only (60%)
rtk test <cmd>          # Generic test wrapper - failures only
```

### Git (59-80% savings)
```bash
rtk git status          # Compact status
rtk git log             # Compact log (works with all git flags)
rtk git diff            # Compact diff (80%)
rtk git show            # Compact show (80%)
rtk git add             # Ultra-compact confirmations (59%)
rtk git commit          # Ultra-compact confirmations (59%)
rtk git push            # Ultra-compact confirmations
rtk git pull            # Ultra-compact confirmations
rtk git branch          # Compact branch list
rtk git fetch           # Compact fetch
rtk git stash           # Compact stash
rtk git worktree        # Compact worktree
```

Note: Git passthrough works for ALL subcommands, even those not explicitly listed.

### GitHub (26-87% savings)
```bash
rtk gh pr view <num>    # Compact PR view (87%)
rtk gh pr checks        # Compact PR checks (79%)
rtk gh run list         # Compact workflow runs (82%)
rtk gh issue list       # Compact issue list (80%)
rtk gh api              # Compact API responses (26%)
```

### JavaScript/TypeScript Tooling (70-90% savings)
```bash
rtk pnpm list           # Compact dependency tree (70%)
rtk pnpm outdated       # Compact outdated packages (80%)
rtk pnpm install        # Compact install output (90%)
rtk npm run <script>    # Compact npm script output
rtk npx <cmd>           # Compact npx command output
rtk prisma              # Prisma without ASCII art (88%)
```

### Files & Search (60-75% savings)
```bash
rtk ls <path>           # Tree format, compact (65%)
rtk read <file>         # Code reading with filtering (60%)
rtk grep <pattern>      # Search grouped by file (75%). Format flags (-c, -l, -L, -o, -Z) run raw.
rtk find <pattern>      # Find grouped by directory (70%)
```

### Analysis & Debug (70-90% savings)
```bash
rtk err <cmd>           # Filter errors only from any command
rtk log <file>          # Deduplicated logs with counts
rtk json <file>         # JSON structure without values
rtk deps                # Dependency overview
rtk env                 # Environment variables compact
rtk summary <cmd>       # Smart summary of command output
rtk diff                # Ultra-compact diffs
```

### Infrastructure (85% savings)
```bash
rtk docker ps           # Compact container list
rtk docker images       # Compact image list
rtk docker logs <c>     # Deduplicated logs
rtk kubectl get         # Compact resource list
rtk kubectl logs        # Deduplicated pod logs
```

### Network (65-70% savings)
```bash
rtk curl <url>          # Compact HTTP responses (70%)
rtk wget <url>          # Compact download output (65%)
```

### Meta Commands
```bash
rtk gain                # View token savings statistics
rtk gain --history      # View command history with savings
rtk discover            # Analyze Claude Code sessions for missed RTK usage
rtk proxy <cmd>         # Run command without filtering (for debugging)
rtk init                # Add RTK instructions to CLAUDE.md
rtk init --global       # Add RTK to ~/.claude/CLAUDE.md
```

## Token Savings Overview

| Category | Commands | Typical Savings |
|----------|----------|-----------------|
| Tests | vitest, playwright, cargo test | 90-99% |
| Build | next, tsc, lint, prettier | 70-87% |
| Git | status, log, diff, add, commit | 59-80% |
| GitHub | gh pr, gh run, gh issue | 26-87% |
| Package Managers | pnpm, npm, npx | 70-90% |
| Files | ls, read, grep, find | 60-75% |
| Infrastructure | docker, kubectl | 85% |
| Network | curl, wget | 65-70% |

Overall average: **60-90% token reduction** on common development operations.
<!-- /rtk-instructions -->