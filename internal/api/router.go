package api

import (
	"log/slog"
	"net/http"
)

// NewRouter builds the HTTP handler: a stdlib ServeMux (Go 1.22 method routing)
// wrapped in the middleware chain. RequestID is outermost so its value is set
// before Recover and Logger run.
func NewRouter(h *Handlers, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /encrypt-file", h.EncryptFile)
	mux.HandleFunc("GET /decrypt-file/{file_id}", h.DecryptFile)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return Chain(mux,
		RequestID,
		Recover(logger),
		Logger(logger),
	)
}
