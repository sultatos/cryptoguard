package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"cryptoguard/internal/service"
)

// Handlers holds the dependencies for the HTTP layer.
type Handlers struct {
	svc    *service.FileService
	logger *slog.Logger
}

func NewHandlers(svc *service.FileService, logger *slog.Logger) *Handlers {
	return &Handlers{svc: svc, logger: logger}
}

type encryptResponse struct {
	FileID       string `json:"file_id"`
	OriginalName string `json:"original_name"`
	Size         int64  `json:"size"`
}

// EncryptFile handles POST /encrypt-file. It reads the multipart body as a
// stream (MultipartReader, not ParseMultipartForm) so large uploads are never
// buffered into memory.
func (h *Handlers) EncryptFile(w http.ResponseWriter, r *http.Request) {
	mr, err := r.MultipartReader()
	if err != nil {
		writeError(w, http.StatusBadRequest, "expected multipart/form-data")
		return
	}

	part, err := nextFilePart(mr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "no file field in form")
		return
	}
	defer part.Close()

	res, err := h.svc.Encrypt(r.Context(), part.FileName(), part)
	if err != nil {
		h.logger.Error("encrypt failed", "err", err)
		writeError(w, http.StatusInternalServerError, "encryption failed")
		return
	}

	writeJSON(w, http.StatusCreated, encryptResponse{
		FileID:       res.FileID.String(),
		OriginalName: res.OriginalName,
		Size:         res.Size,
	})
}

// DecryptFile handles GET /decrypt-file/{file_id}. It resolves not-found before
// writing any body, then streams the decrypted file as an attachment.
func (h *Handlers) DecryptFile(w http.ResponseWriter, r *http.Request) {
	// Parsing as a UUID both validates input and guarantees the value can't be
	// used for path traversal downstream.
	id, err := uuid.Parse(r.PathValue("file_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid file_id")
		return
	}

	ds, err := h.svc.OpenForDecrypt(r.Context(), id)
	if errors.Is(err, service.ErrNotFound) {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}
	if err != nil {
		h.logger.Error("open for decrypt failed", "err", err, "file_id", id)
		writeError(w, http.StatusInternalServerError, "decryption failed")
		return
	}
	defer ds.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", contentDisposition(ds.OriginalName))

	// Headers/200 are committed once the body starts. If a later chunk fails
	// authentication we can only log and drop the connection — we cannot change
	// the status code. This is inherent to streaming an authenticated download.
	if err := ds.WriteTo(w); err != nil {
		h.logger.Error("stream decrypt failed mid-body", "err", err, "file_id", id)
	}
}

// nextFilePart returns the first part that carries a file (has a filename).
func nextFilePart(mr *multipart.Reader) (*multipart.Part, error) {
	for {
		part, err := mr.NextPart()
		if err != nil {
			return nil, err
		}
		if part.FileName() != "" {
			return part, nil
		}
		_ = part.Close()
	}
}

// contentDisposition builds an RFC 6266 header with a sanitized ASCII fallback
// and a UTF-8 filename*, so odd characters in the name can't break the header.
func contentDisposition(name string) string {
	if name == "" {
		name = "download"
	}
	ascii := strings.Map(func(r rune) rune {
		if r < 0x20 || r == '"' || r == '\\' || r > 0x7e {
			return '_'
		}
		return r
	}, name)
	return fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, ascii, url.PathEscape(name))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
