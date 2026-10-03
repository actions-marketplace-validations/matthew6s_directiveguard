package scanner

import (
	"fmt"
	"strings"
)

type Severity int

const (
	SeverityNone Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
)

func (s Severity) String() string {
	switch s {
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "none"
	}
}

func ParseThreshold(value string) (Severity, error) {
	switch strings.ToLower(value) {
	case "none":
		return SeverityNone, nil
	case "low":
		return SeverityLow, nil
	case "medium":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	default:
		return SeverityNone, fmt.Errorf("unknown severity %q (want low, medium, high, or none)", value)
	}
}

type Finding struct {
	RuleID      string   `json:"rule_id"`
	Severity    Severity `json:"-"`
	Level       string   `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Path        string   `json:"path"`
	Line        int      `json:"line"`
	Snippet     string   `json:"snippet,omitempty"`
	Remediation string   `json:"remediation"`
}

type Result struct {
	Root         string    `json:"root"`
	FilesScanned int       `json:"files_scanned"`
	Findings     []Finding `json:"findings"`
}

func (r Result) Fails(threshold Severity) bool {
	if threshold == SeverityNone {
		return false
	}
	for _, finding := range r.Findings {
		if finding.Severity >= threshold {
			return true
		}
	}
	return false
}
