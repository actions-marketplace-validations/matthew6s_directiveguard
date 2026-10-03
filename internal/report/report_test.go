package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/matthew6s/agentshield/internal/scanner"
)

func TestFormats(t *testing.T) {
	result := scanner.Result{Root: "/repo", FilesScanned: 1, Findings: []scanner.Finding{{
		RuleID: "ASI001", Severity: scanner.SeverityHigh, Level: "high", Title: "Unsafe",
		Description: "Description", Path: "AGENTS.md", Line: 2, Remediation: "Fix it",
	}}}
	for _, format := range []string{"json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			var output bytes.Buffer
			if err := Write(&output, format, result); err != nil {
				t.Fatalf("Write: %v", err)
			}
			var decoded any
			if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
		})
	}
	var output bytes.Buffer
	if err := Write(&output, "text", result); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !strings.Contains(output.String(), "ASI001 HIGH") {
		t.Fatalf("unexpected text output: %s", output.String())
	}
}
