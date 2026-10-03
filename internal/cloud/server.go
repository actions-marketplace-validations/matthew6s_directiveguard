package cloud

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

//go:embed web/*
var webFiles embed.FS

type Server struct {
	config        Config
	store         *Store
	client        *http.Client
	logger        *slog.Logger
	secureCookies bool
}

func NewServer(config Config, store *Store, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{config: config, store: store, logger: logger, client: &http.Client{Timeout: 15 * time.Second}, secureCookies: strings.HasPrefix(config.BaseURL, "https://")}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.home)
	mux.HandleFunc("GET /app", s.app)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /login/github", s.loginGitHub)
	mux.HandleFunc("GET /auth/github/callback", s.githubCallback)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /api/me", withUser(s.me, s))
	mux.HandleFunc("GET /api/projects", withUser(s.projects, s))
	mux.HandleFunc("POST /api/projects", withUser(s.createProject, s))
	mux.HandleFunc("POST /api/projects/{id}/keys", withUser(s.createKey, s))
	mux.HandleFunc("GET /api/projects/{id}/keys", withUser(s.listKeys, s))
	mux.HandleFunc("DELETE /api/projects/{id}/keys/{keyID}", withUser(s.deleteKey, s))
	mux.HandleFunc("GET /api/scans", withUser(s.scans, s))
	mux.HandleFunc("POST /api/v1/scans", s.ingestScan)
	mux.HandleFunc("POST /api/billing/checkout", withUser(s.createCheckout, s))
	mux.HandleFunc("POST /api/billing/portal", withUser(s.createPortal, s))
	mux.HandleFunc("POST /webhooks/stripe", s.stripeWebhook)
	return s.securityHeaders(s.recoverPanics(s.logRequests(mux)))
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	data, err := webFiles.ReadFile("web/index.html")
	if err != nil {
		s.internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}
func (s *Server) app(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.currentUser(r); !ok {
		http.Redirect(w, r, "/login/github", http.StatusFound)
		return
	}
	data, err := webFiles.ReadFile("web/app.html")
	if err != nil {
		s.internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"user": user, "billing_enabled": s.config.BillingEnabled()})
}
func (s *Server) projects(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	projects, err := s.store.Projects(r.Context(), user.ID)
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, projects)
}

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$`)

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	if !s.csrfValid(r) {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}
	if err := requireJSON(r); err != nil {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": err.Error()})
		return
	}
	user := userFromContext(r.Context())
	limit := 1
	if user.Plan == "team" {
		limit = 25
	}
	count, err := s.store.ProjectCount(r.Context(), user.ID)
	if err != nil {
		s.internalError(w, err)
		return
	}
	if count >= limit {
		writeJSON(w, http.StatusPaymentRequired, map[string]string{"error": "project limit reached; upgrade to Team"})
		return
	}
	var input struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if decodeJSON(w, r, &input) != nil {
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Slug = strings.ToLower(strings.TrimSpace(input.Slug))
	if len(input.Name) < 2 || len(input.Name) > 80 || !slugPattern.MatchString(input.Slug) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name or slug is invalid"})
		return
	}
	project, err := s.store.CreateProject(r.Context(), user.ID, input.Name, input.Slug)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "project slug already exists"})
		return
	}
	writeJSON(w, http.StatusCreated, project)
}

func (s *Server) createKey(w http.ResponseWriter, r *http.Request) {
	if !s.csrfValid(r) {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}
	user := userFromContext(r.Context())
	projectID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if _, err = s.store.ProjectOwned(r.Context(), projectID, user.ID); err != nil {
		http.NotFound(w, r)
		return
	}
	var input struct {
		Name string `json:"name"`
	}
	if decodeJSON(w, r, &input) != nil {
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" || len(input.Name) > 80 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key name is invalid"})
		return
	}
	secret, err := randomToken(32)
	if err != nil {
		s.internalError(w, err)
		return
	}
	raw := "as_live_" + secret
	key, err := s.store.InsertAPIKey(r.Context(), projectID, input.Name, raw[:16], keyHash(raw))
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"key": key, "secret": raw, "warning": "This secret is shown once. Store it securely."})
}

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	projectID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	keys, err := s.store.APIKeys(r.Context(), projectID, user.ID)
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, keys)
}
func (s *Server) deleteKey(w http.ResponseWriter, r *http.Request) {
	if !s.csrfValid(r) {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}
	user := userFromContext(r.Context())
	projectID, err1 := strconv.ParseInt(r.PathValue("id"), 10, 64)
	keyID, err2 := strconv.ParseInt(r.PathValue("keyID"), 10, 64)
	if err1 != nil || err2 != nil {
		http.NotFound(w, r)
		return
	}
	deleted, err := s.store.DeleteAPIKey(r.Context(), keyID, projectID, user.ID)
	if err != nil {
		s.internalError(w, err)
		return
	}
	if !deleted {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) ingestScan(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" || token == r.Header.Get("Authorization") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Bearer API key required"})
		return
	}
	project, user, err := s.store.ProjectByAPIKey(r.Context(), keyHash(token))
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid API key"})
		return
	}
	monthlyLimit := 100
	if user.Plan == "team" {
		monthlyLimit = 5000
	}
	start := time.Now().UTC()
	start = time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, time.UTC)
	used, err := s.store.ScansSinceUser(r.Context(), user.ID, start)
	if err != nil {
		s.internalError(w, err)
		return
	}
	if used >= monthlyLimit {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "monthly scan limit reached"})
		return
	}
	var upload ScanUpload
	if decodeJSON(w, r, &upload) != nil {
		return
	}
	if upload.FilesScanned < 0 || upload.FilesScanned > 1_000_000 || len(upload.Findings) > 10_000 || len(upload.CommitSHA) > 64 || len(upload.Branch) > 255 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "scan payload exceeds limits"})
		return
	}
	for _, finding := range upload.Findings {
		if finding.RuleID == "" || len(finding.Path) > 1024 || finding.Line < 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid finding"})
			return
		}
	}
	scan, err := s.store.InsertScan(r.Context(), project.ID, upload)
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, scan)
}
func (s *Server) scans(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	since := time.Unix(0, 0)
	if user.Plan == "free" {
		since = time.Now().AddDate(0, 0, -30)
	}
	scans, err := s.store.Scans(r.Context(), user.ID, since, 100)
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, scans)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON payload"})
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request must contain one JSON object"})
		return fmt.Errorf("trailing JSON")
	}
	return nil
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func (s *Server) internalError(w http.ResponseWriter, err error) {
	s.logger.Error("request failed", "error", err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
}
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}
func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if value := recover(); value != nil {
				s.logger.Error("panic", "value", value)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.logger.Info("request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}
