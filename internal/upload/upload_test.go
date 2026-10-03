package upload

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matthew6s/directiveguard/internal/scanner"
)

func TestSend(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("wrong authorization")
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if payload["commit_sha"] != "abc" {
			t.Errorf("wrong payload: %+v", payload)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	result := scanner.Result{FilesScanned: 2, Findings: []scanner.Finding{{RuleID: "ASI001", Level: "high", Title: "Unsafe", Path: "AGENTS.md", Line: 1}}}
	if err := Send(context.Background(), server.URL, "secret", result, Metadata{CommitSHA: "abc", Branch: "main"}); err != nil {
		t.Fatal(err)
	}
}
func TestSendRequiresKey(t *testing.T) {
	if err := Send(context.Background(), "http://example.invalid", "", scanner.Result{}, Metadata{}); err == nil {
		t.Fatal("missing key accepted")
	}
}
