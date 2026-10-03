package cloud

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProjectKeyAndScanFlow(t *testing.T) {
	server, store := testServer(t)
	user, err := store.UpsertUser(context.Background(), 101, "octocat", "", "")
	if err != nil {
		t.Fatal(err)
	}

	response := authenticatedRequest(t, server, user.ID, http.MethodPost, "/api/projects", `{"name":"Demo Project","slug":"demo-project"}`)
	if response.Code != http.StatusCreated {
		t.Fatalf("create project = %d: %s", response.Code, response.Body.String())
	}
	var project Project
	decodeResponse(t, response, &project)

	response = authenticatedRequest(t, server, user.ID, http.MethodPost, fmt.Sprintf("/api/projects/%d/keys", project.ID), `{"name":"CI"}`)
	if response.Code != http.StatusCreated {
		t.Fatalf("create key = %d: %s", response.Code, response.Body.String())
	}
	var keyResponse struct {
		Key    APIKey `json:"key"`
		Secret string `json:"secret"`
	}
	decodeResponse(t, response, &keyResponse)
	if !strings.HasPrefix(keyResponse.Secret, "as_live_") {
		t.Fatalf("unexpected key %q", keyResponse.Secret)
	}

	payload := `{"commit_sha":"abc123","branch":"main","files_scanned":3,"findings":[{"rule_id":"ASI001","severity":"high","title":"Unsafe","path":"AGENTS.md","line":2}]}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(payload))
	request.Header.Set("Authorization", "Bearer "+keyResponse.Secret)
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("upload scan = %d: %s", response.Code, response.Body.String())
	}
	var scan Scan
	decodeResponse(t, response, &scan)
	if scan.High != 1 || scan.FilesScanned != 3 {
		t.Fatalf("unexpected scan: %+v", scan)
	}

	response = authenticatedRequest(t, server, user.ID, http.MethodGet, "/api/scans", "")
	var scans []Scan
	decodeResponse(t, response, &scans)
	if len(scans) != 1 || scans[0].High != 1 {
		t.Fatalf("unexpected scans: %+v", scans)
	}

	response = authenticatedRequest(t, server, user.ID, http.MethodGet, fmt.Sprintf("/api/projects/%d/keys", project.ID), "")
	var keys []APIKey
	decodeResponse(t, response, &keys)
	if len(keys) != 1 || keys[0].Prefix == "" {
		t.Fatalf("unexpected keys: %+v", keys)
	}
	response = authenticatedRequest(t, server, user.ID, http.MethodDelete, fmt.Sprintf("/api/projects/%d/keys/%d", project.ID, keyResponse.Key.ID), "")
	if response.Code != http.StatusNoContent {
		t.Fatalf("delete key = %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(payload))
	request.Header.Set("Authorization", "Bearer "+keyResponse.Secret)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked key upload = %d", response.Code)
	}
}

func TestProjectOwnershipBoundary(t *testing.T) {
	server, store := testServer(t)
	owner, _ := store.UpsertUser(context.Background(), 201, "owner", "", "")
	other, _ := store.UpsertUser(context.Background(), 202, "other", "", "")
	project, err := store.CreateProject(context.Background(), owner.ID, "Private", "private-project")
	if err != nil {
		t.Fatal(err)
	}
	response := authenticatedRequest(t, server, other.ID, http.MethodPost, fmt.Sprintf("/api/projects/%d/keys", project.ID), `{"name":"stolen"}`)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", response.Code)
	}
}

func TestInvalidAPIKeyRejected(t *testing.T) {
	server, _ := testServer(t)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(`{"files_scanned":1,"findings":[]}`))
	request.Header.Set("Authorization", "Bearer as_live_invalid")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", response.Code)
	}
}

func TestSignedCookieTampering(t *testing.T) {
	server, _ := testServer(t)
	recorder := httptest.NewRecorder()
	server.setSignedCookie(recorder, "session", "123", time.Hour)
	cookie := recorder.Result().Cookies()[0]
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	cookie.Value += "x"
	request.AddCookie(cookie)
	if _, ok := server.readSignedCookie(request, "session"); ok {
		t.Fatal("tampered cookie accepted")
	}
}

func TestStripeSignature(t *testing.T) {
	body := []byte(`{"type":"test"}`)
	secret := "whsec_test"
	now := time.Now()
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", now.Unix())
	mac.Write(body)
	header := fmt.Sprintf("t=%d,v1=%s", now.Unix(), hex.EncodeToString(mac.Sum(nil)))
	if !verifyStripeSignature(body, header, secret, now) {
		t.Fatal("valid signature rejected")
	}
	if verifyStripeSignature([]byte("changed"), header, secret, now) {
		t.Fatal("changed body accepted")
	}
	if verifyStripeSignature(body, header, secret, now.Add(10*time.Minute)) {
		t.Fatal("expired signature accepted")
	}
}

func TestStripeCheckoutAndWebhook(t *testing.T) {
	var checkoutForm string
	stripe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		checkoutForm = string(data)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"url":"https://checkout.stripe.test/session"}`))
	}))
	defer stripe.Close()
	server, store := testServer(t)
	server.config.StripeAPIBase = stripe.URL
	server.config.StripeSecretKey = "sk_test"
	server.config.StripeWebhookSecret = "whsec_test"
	server.config.StripeTeamPriceID = "price_team"
	user, err := store.UpsertUser(context.Background(), 301, "buyer", "buyer@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	response := authenticatedRequest(t, server, user.ID, http.MethodPost, "/api/billing/checkout", `{}`)
	if response.Code != http.StatusOK {
		t.Fatalf("checkout=%d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(checkoutForm, "price_team") || !strings.Contains(checkoutForm, "client_reference_id") {
		t.Fatalf("unexpected checkout form: %s", checkoutForm)
	}
	body := []byte(fmt.Sprintf(`{"type":"checkout.session.completed","data":{"object":{"customer":"cus_test","client_reference_id":"%d"}}}`, user.ID))
	now := time.Now()
	mac := hmac.New(sha256.New, []byte(server.config.StripeWebhookSecret))
	fmt.Fprintf(mac, "%d.", now.Unix())
	mac.Write(body)
	request := httptest.NewRequest(http.MethodPost, "/webhooks/stripe", bytes.NewReader(body))
	request.Header.Set("Stripe-Signature", fmt.Sprintf("t=%d,v1=%s", now.Unix(), hex.EncodeToString(mac.Sum(nil))))
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("webhook=%d: %s", response.Code, response.Body.String())
	}
	updated, err := store.UserByID(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Plan != "team" || updated.StripeCustomerID != "cus_test" {
		t.Fatalf("billing not updated: %+v", updated)
	}
}

func TestHealthAndSecurityHeaders(t *testing.T) {
	server, _ := testServer(t)
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d", response.Code)
	}
	if response.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("missing CSP")
	}
}

func testServer(t *testing.T) (*Server, *Store) {
	t.Helper()
	store, err := OpenStore("file:" + strings.ReplaceAll(t.Name(), "/", "-") + "?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	config := Config{BaseURL: "http://example.test", SessionSecret: bytes.Repeat([]byte{42}, 32)}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewServer(config, store, logger), store
}
func authenticatedRequest(t *testing.T, server *Server, userID int64, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Origin", server.config.BaseURL)
	cookieRecorder := httptest.NewRecorder()
	server.setSignedCookie(cookieRecorder, "session", fmt.Sprint(userID), time.Hour)
	request.AddCookie(cookieRecorder.Result().Cookies()[0])
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}
func decodeResponse(t *testing.T, response *httptest.ResponseRecorder, destination any) {
	t.Helper()
	if err := json.NewDecoder(response.Body).Decode(destination); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, response.Body.String())
	}
}
