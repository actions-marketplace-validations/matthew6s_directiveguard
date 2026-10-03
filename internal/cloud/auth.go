package cloud

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

func (s *Server) loginGitHub(w http.ResponseWriter, r *http.Request) {
	if !s.config.GitHubEnabled() {
		http.Error(w, "GitHub login is not configured", http.StatusServiceUnavailable)
		return
	}
	state, err := randomToken(24)
	if err != nil {
		s.internalError(w, err)
		return
	}
	s.setSignedCookie(w, "oauth_state", state, 10*time.Minute)
	params := url.Values{"client_id": {s.config.GitHubClientID}, "redirect_uri": {s.config.BaseURL + "/auth/github/callback"}, "scope": {"read:user user:email"}, "state": {state}}
	http.Redirect(w, r, "https://github.com/login/oauth/authorize?"+params.Encode(), http.StatusFound)
}

func (s *Server) githubCallback(w http.ResponseWriter, r *http.Request) {
	state, ok := s.readSignedCookie(r, "oauth_state")
	if !ok || state == "" || !hmac.Equal([]byte(state), []byte(r.URL.Query().Get("state"))) {
		http.Error(w, "invalid OAuth state", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing OAuth code", http.StatusBadRequest)
		return
	}
	form := url.Values{"client_id": {s.config.GitHubClientID}, "client_secret": {s.config.GitHubClientSecret}, "code": {code}, "redirect_uri": {s.config.BaseURL + "/auth/github/callback"}}
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, "https://github.com/login/oauth/access_token", strings.NewReader(form.Encode()))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		s.internalError(w, err)
		return
	}
	defer resp.Body.Close()
	var token struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&token); err != nil || token.AccessToken == "" {
		http.Error(w, "GitHub authentication failed", http.StatusBadGateway)
		return
	}
	apiReq, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://api.github.com/user", nil)
	apiReq.Header.Set("Authorization", "Bearer "+token.AccessToken)
	apiReq.Header.Set("Accept", "application/vnd.github+json")
	apiResp, err := s.client.Do(apiReq)
	if err != nil {
		s.internalError(w, err)
		return
	}
	defer apiResp.Body.Close()
	var profile githubUser
	if apiResp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(apiResp.Body, 1<<20)).Decode(&profile) != nil {
		http.Error(w, "GitHub profile lookup failed", http.StatusBadGateway)
		return
	}
	user, err := s.store.UpsertUser(r.Context(), profile.ID, profile.Login, profile.Email, profile.AvatarURL)
	if err != nil {
		s.internalError(w, err)
		return
	}
	s.setSignedCookie(w, "session", strconv.FormatInt(user.ID, 10), 7*24*time.Hour)
	http.SetCookie(w, &http.Cookie{Name: "oauth_state", MaxAge: -1, Path: "/", HttpOnly: true, Secure: s.secureCookies, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/app", http.StatusFound)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "session", MaxAge: -1, Path: "/", HttpOnly: true, Secure: s.secureCookies, SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) currentUser(r *http.Request) (User, bool) {
	value, ok := s.readSignedCookie(r, "session")
	if !ok {
		return User{}, false
	}
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return User{}, false
	}
	user, err := s.store.UserByID(r.Context(), id)
	return user, err == nil
}

func (s *Server) setSignedCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	expires := time.Now().Add(ttl).Unix()
	payload := value + "|" + strconv.FormatInt(expires, 10)
	signature := s.sign(payload)
	http.SetCookie(w, &http.Cookie{Name: name, Value: base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + signature, Path: "/", MaxAge: int(ttl.Seconds()), HttpOnly: true, Secure: s.secureCookies, SameSite: http.SameSiteLaxMode})
}
func (s *Server) readSignedCookie(r *http.Request, name string) (string, bool) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || !hmac.Equal([]byte(s.sign(string(raw))), []byte(parts[1])) {
		return "", false
	}
	fields := strings.Split(string(raw), "|")
	if len(fields) != 2 {
		return "", false
	}
	expires, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || time.Now().Unix() > expires {
		return "", false
	}
	return fields[0], true
}
func (s *Server) sign(value string) string {
	mac := hmac.New(sha256.New, s.config.SessionSecret)
	mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func randomToken(bytes int) (string, error) {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
func keyHash(key string) []byte { sum := sha256.Sum256([]byte(key)); return sum[:] }

type userContextKey struct{}

func withUser(next http.HandlerFunc, s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := s.currentUser(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), userContextKey{}, user)))
	}
}
func userFromContext(ctx context.Context) User { return ctx.Value(userContextKey{}).(User) }

func (s *Server) csrfValid(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	return origin == "" || origin == s.config.BaseURL
}
func requireJSON(r *http.Request) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return fmt.Errorf("Content-Type must be application/json")
	}
	return nil
}
