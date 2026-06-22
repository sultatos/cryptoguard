# AI Usage Log

The take-home brief asks for a high-level record of AI assistant usage. Per the
brief, I remain the owner of and am accountable for all code here.

## Tools used

- **Claude** — used for (a) an architecture/implementation plan, (b) scaffolding
  the initial package layout, the chunked streaming-AEAD design, the sqlc setup,
  and the HTTP/middleware boilerplate.

## What was AI-influenced vs. authored/owned by me

- **Crypto design (`internal/crypto`)** — chunked AES-256-GCM framing with
  counter+final-flag nonces (truncation/reordering resistant). AI-assisted; I
  reviewed every line and the test suite covers the security properties.
- **Layout & wiring** — config, storage, repository, service, api, main:
  AI-scaffolded, then reviewed/edited by me.
- **Tests** — crypto unit tests and the API integration tests: AI-assisted and gated
  behind the `integration` build tag and backed by a real Postgres via
  testcontainers.

## My responsibility

I have read, understood, and can debug and defend every part of this codebase,
including the cryptographic decisions and their trade-offs. (See the "Design
decisions" section of the README.)