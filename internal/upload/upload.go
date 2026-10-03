package upload

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/matthew6s/agentshield/internal/scanner"
)

type Metadata struct{ CommitSHA, Branch string }

func Send(ctx context.Context, baseURL, apiKey string, result scanner.Result, metadata Metadata) error {
	if apiKey == "" {
		return fmt.Errorf("AGENTSHIELD_API_KEY is required when --upload is set")
	}
	findings := make([]map[string]any, 0, len(result.Findings))
	for _, finding := range result.Findings {
		findings = append(findings, map[string]any{"rule_id": finding.RuleID, "severity": finding.Level, "title": finding.Title, "description": finding.Description, "path": finding.Path, "line": finding.Line, "remediation": finding.Remediation})
	}
	payload := map[string]any{"commit_sha": metadata.CommitSHA, "branch": metadata.Branch, "files_scanned": result.FilesScanned, "findings": findings}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/api/v1/scans", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+apiKey)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "AgentShield CLI")
	client := &http.Client{Timeout: 20 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("upload scan: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("upload scan: server returned %s: %s", response.Status, strings.TrimSpace(string(data)))
	}
	return nil
}
