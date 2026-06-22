//go:build integration

// Integration tests for the full HTTP round trip. They spin up a real Postgres
// via testcontainers, so they need Docker available and are gated behind the
// `integration` build tag:
//
//	go test -tags=integration ./internal/api/...
//
// Add the test deps first:
//
//	go get github.com/testcontainers/testcontainers-go \
//	       github.com/testcontainers/testcontainers-go/modules/postgres

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"cryptoguard/internal/repository"
	"cryptoguard/internal/service"
	"cryptoguard/internal/storage"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	ctx := context.Background()

	pg, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("cryptoguard"),
		tcpostgres.WithUsername("cryptoguard"),
		tcpostgres.WithPassword("cryptoguard"), testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(60*time.Second)),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() { _ = pg.Terminate(ctx) })

	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}

	pool, err := repository.NewPool(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	// Apply schema.
	schema, err := io.ReadAll(mustOpen(t, "../../migrations/0001_init.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(schema)); err != nil {
		t.Fatalf("apply schema: %v", err)
	}

	blobs, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	kek := bytes.Repeat([]byte{0x42}, 32)
	svc := service.New(repository.New(pool), blobs, kek)
	srv := httptest.NewServer(NewRouter(NewHandlers(svc, slog.Default()), slog.Default()))
	t.Cleanup(srv.Close)

	// Upload a payload larger than one chunk.
	payload := bytes.Repeat([]byte("cryptoguard-"), 20000)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "report.bin")
	_, _ = fw.Write(payload)
	_ = mw.Close()

	resp, err := http.Post(srv.URL+"/encrypt-file", mw.FormDataContentType(), &body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("encrypt status = %d", resp.StatusCode)
	}

	var enc encryptResponse
	if err := decodeJSON(resp.Body, &enc); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Download and compare.
	dres, err := http.Get(srv.URL + "/decrypt-file/" + enc.FileID)
	if err != nil {
		t.Fatal(err)
	}
	defer dres.Body.Close()
	if dres.StatusCode != http.StatusOK {
		t.Fatalf("decrypt status = %d", dres.StatusCode)
	}
	got, _ := io.ReadAll(dres.Body)
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(payload))
	}

	// Unknown id -> 404.
	nres, _ := http.Get(srv.URL + "/decrypt-file/" + "00000000-0000-0000-0000-000000000000")
	if nres.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown id status = %d, want 404", nres.StatusCode)
	}
	nres.Body.Close()
}

func mustOpen(t *testing.T, path string) io.Reader {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func decodeJSON(r io.Reader, v any) error {
	return json.NewDecoder(r).Decode(v)
}
