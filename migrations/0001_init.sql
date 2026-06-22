-- 0001_init.sql
-- This file is both the runtime migration and sqlc's schema source
-- (sqlc.yaml points its `schema:` at the migrations/ directory).

CREATE TABLE files (
    file_id           UUID PRIMARY KEY,
    original_filename TEXT        NOT NULL,
    encrypted_dek     BYTEA       NOT NULL,   -- nonce || GCM(KEK, DEK)
    size_bytes        BIGINT      NOT NULL,   -- original plaintext size
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
