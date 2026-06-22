-- queries.sql — input to sqlc. Each `-- name:` block becomes a method on *Queries.
-- The trailing tag controls the return shape:
--   :one  -> returns a single row (error if zero)
--   :many -> returns a slice
--   :exec -> returns only error (no rows)

-- name: CreateFile :one
INSERT INTO files (file_id, original_filename, encrypted_dek, size_bytes)
VALUES ($1, $2, $3, $4)
RETURNING file_id, original_filename, encrypted_dek, size_bytes, created_at;

-- name: GetFile :one
SELECT file_id, original_filename, encrypted_dek, size_bytes, created_at
FROM files
WHERE file_id = $1;

-- DeleteFile is the compensating action when the DB insert succeeds but a later
-- step fails, or for the orphan sweep. Keeps the "row exists => blob exists" invariant.
-- name: DeleteFile :exec
DELETE FROM files
WHERE file_id = $1;
