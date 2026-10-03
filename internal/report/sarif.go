package report

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/matthew6s/agentshield/internal/scanner"
)

type sarifDocument struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string         `json:"id"`
	ShortDescription sarifMessage   `json:"shortDescription"`
	Help             sarifMessage   `json:"help"`
	Properties       map[string]any `json:"properties"`
}
type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}
type sarifMessage struct {
	Text string `json:"text"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}
type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func writeSARIF(writer io.Writer, result scanner.Result) error {
	rules := make(map[string]sarifRule)
	results := make([]sarifResult, 0, len(result.Findings))
	for _, finding := range result.Findings {
		rules[finding.RuleID] = sarifRule{ID: finding.RuleID,
			ShortDescription: sarifMessage{Text: finding.Title},
			Help:             sarifMessage{Text: finding.Remediation},
			Properties:       map[string]any{"security-severity": securityScore(finding.Level)},
		}
		results = append(results, sarifResult{RuleID: finding.RuleID, Level: sarifLevel(finding.Level),
			Message: sarifMessage{Text: finding.Description}, Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: finding.Path}, Region: sarifRegion{StartLine: finding.Line},
			}}}})
	}
	ruleList := make([]sarifRule, 0, len(rules))
	for _, rule := range rules {
		ruleList = append(ruleList, rule)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })
	document := sarifDocument{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "AgentShield", InformationURI: "https://github.com/matthew6s/agentshield", Rules: ruleList}}, Results: results}}}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

func sarifLevel(level string) string {
	if level == "high" || level == "medium" {
		return "error"
	}
	return "warning"
}

func securityScore(level string) string {
	switch level {
	case "high":
		return "8.0"
	case "medium":
		return "5.0"
	default:
		return "2.0"
	}
}
