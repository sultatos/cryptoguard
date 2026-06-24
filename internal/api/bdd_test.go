//go:build integration

// Cucumber/Gherkin (godog) integration tests for the HTTP API. They exercise
// the same full round trip as handlers_test.go but as executable specifications
// living in features/*.feature.
//
// One real Postgres (via testcontainers) and one httptest server are started
// once for the whole suite and shared across scenarios:
//
//	go test -tags=integration ./internal/api/...
//
// Docker must be available.

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"cryptoguard/internal/repository"
	"cryptoguard/internal/service"
	"cryptoguard/internal/storage"
)

// suiteEnv holds the infrastructure shared by every scenario. It is built once
// in BeforeSuite and torn down in AfterSuite.
type suiteEnv struct {
	pg      testcontainers.Container
	pool    interface{ Close() }
	server  *httptest.Server
	baseURL string
}

var env suiteEnv

func TestFeatures(t *testing.T) {
	suite := godog.TestSuite{
		Name:                 "cryptoguard",
		TestSuiteInitializer: initializeSuite,
		ScenarioInitializer:  initializeScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"features"},
			TestingT: t,
			Strict:   true,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog: non-zero status, feature tests failed")
	}
}

// initializeSuite stands up Postgres + the HTTP server before any scenario runs
// and tears them down afterwards.
func initializeSuite(sc *godog.TestSuiteContext) {
	sc.BeforeSuite(func() {
		ctx := context.Background()

		pg, err := tcpostgres.Run(ctx, "postgres:16-alpine",
			tcpostgres.WithDatabase("cryptoguard"),
			tcpostgres.WithUsername("cryptoguard"),
			tcpostgres.WithPassword("cryptoguard"),
			testcontainers.WithWaitStrategy(
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).WithStartupTimeout(60*time.Second)),
		)
		mustNot(err, "start postgres")

		dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
		mustNot(err, "connection string")

		pool, err := repository.NewPool(ctx, dsn)
		mustNot(err, "new pool")

		schema, err := os.ReadFile("../../migrations/0001_init.sql")
		mustNot(err, "read schema")
		_, err = pool.Exec(ctx, string(schema))
		mustNot(err, "apply schema")

		blobs, err := storage.New(must(os.MkdirTemp("", "cryptoguard-bdd-*")))
		mustNot(err, "new blob store")

		kek := bytes.Repeat([]byte{0x42}, 32)
		svc := service.New(repository.New(pool), blobs, kek)
		srv := httptest.NewServer(NewRouter(NewHandlers(svc, slog.Default()), slog.Default()))

		env = suiteEnv{pg: pg, pool: pool, server: srv, baseURL: srv.URL}
	})

	sc.AfterSuite(func() {
		if env.server != nil {
			env.server.Close()
		}
		if env.pool != nil {
			env.pool.Close()
		}
		if env.pg != nil {
			_ = env.pg.Terminate(context.Background())
		}
	})
}

// apiWorld is per-scenario state: the last request's response and the bytes
// involved, so Then steps can assert on what When steps produced.
type apiWorld struct {
	payload    []byte
	status     int
	respBody   []byte
	fileID     string
	downloaded []byte
}

func initializeScenario(sc *godog.ScenarioContext) {
	w := &apiWorld{}

	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		*w = apiWorld{}
		return ctx, nil
	})

	sc.Step(`^a running CryptoGuard service$`, w.serviceIsRunning)
	sc.Step(`^I encrypt a file named "([^"]*)" with (\d+) bytes of content$`, w.encryptFile)
	sc.Step(`^I request decryption of file id "([^"]*)"$`, w.requestDecrypt)
	sc.Step(`^I submit a multipart form with no file field$`, w.submitNoFileField)
	sc.Step(`^the response status is (\d+)$`, w.responseStatusIs)
	sc.Step(`^the encrypted file can be downloaded$`, w.downloadEncrypted)
	sc.Step(`^the downloaded content matches the original$`, w.downloadMatches)
}

func (w *apiWorld) serviceIsRunning() error {
	if env.baseURL == "" {
		return fmt.Errorf("suite not initialized: no base URL")
	}
	return nil
}

func (w *apiWorld) encryptFile(name string, size int) error {
	w.payload = deterministicBytes(size)

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", name)
	if err != nil {
		return err
	}
	if _, err := fw.Write(w.payload); err != nil {
		return err
	}
	if err := mw.Close(); err != nil {
		return err
	}

	resp, err := http.Post(env.baseURL+"/encrypt-file", mw.FormDataContentType(), &body)
	if err != nil {
		return err
	}
	return w.capture(resp)
}

func (w *apiWorld) requestDecrypt(id string) error {
	resp, err := http.Get(env.baseURL + "/decrypt-file/" + id)
	if err != nil {
		return err
	}
	return w.capture(resp)
}

func (w *apiWorld) submitNoFileField() error {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("note", "no file here"); err != nil {
		return err
	}
	if err := mw.Close(); err != nil {
		return err
	}

	resp, err := http.Post(env.baseURL+"/encrypt-file", mw.FormDataContentType(), &body)
	if err != nil {
		return err
	}
	return w.capture(resp)
}

func (w *apiWorld) responseStatusIs(want int) error {
	if w.status != want {
		return fmt.Errorf("response status = %d, want %d (body: %s)", w.status, want, w.respBody)
	}
	return nil
}

func (w *apiWorld) downloadEncrypted() error {
	var enc encryptResponse
	if err := json.Unmarshal(w.respBody, &enc); err != nil {
		return fmt.Errorf("decode encrypt response: %w", err)
	}
	if enc.FileID == "" {
		return fmt.Errorf("encrypt response carried no file_id")
	}
	w.fileID = enc.FileID

	resp, err := http.Get(env.baseURL + "/decrypt-file/" + enc.FileID)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download status = %d, want 200", resp.StatusCode)
	}
	w.downloaded, err = io.ReadAll(resp.Body)
	return err
}

func (w *apiWorld) downloadMatches() error {
	if !bytes.Equal(w.downloaded, w.payload) {
		return fmt.Errorf("round-trip mismatch: got %d bytes, want %d", len(w.downloaded), len(w.payload))
	}
	return nil
}

// capture records the status and full body of a response, then closes it, so
// later steps can assert without holding the connection open.
func (w *apiWorld) capture(resp *http.Response) error {
	defer resp.Body.Close()
	w.status = resp.StatusCode
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	w.respBody = b
	return nil
}

// deterministicBytes returns exactly n bytes of repeating, recognisable content
// so a round-trip mismatch is easy to diagnose.
func deterministicBytes(n int) []byte {
	if n == 0 {
		return []byte{}
	}
	pattern := []byte("cryptoguard-")
	out := bytes.Repeat(pattern, n/len(pattern)+1)
	return out[:n]
}

func must[T any](v T, err error) T {
	mustNot(err, "setup")
	return v
}

func mustNot(err error, what string) {
	if err != nil {
		panic(fmt.Sprintf("bdd suite: %s: %v", what, err))
	}
}
