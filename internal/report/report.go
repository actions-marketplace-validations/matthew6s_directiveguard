package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/matthew6s/directiveguard/internal/scanner"
)

func Write(writer io.Writer, format string, result scanner.Result) error {
	switch strings.ToLower(format) {
	case "text":
		return writeText(writer, result)
	case "json":
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	case "sarif":
		return writeSARIF(writer, result)
	default:
		return fmt.Errorf("unknown format %q (want text, json, or sarif)", format)
	}
}

func writeText(writer io.Writer, result scanner.Result) error {
	if len(result.Findings) == 0 {
		_, err := fmt.Fprintf(writer, "DirectiveGuard: no findings (%d files scanned)\n", result.FilesScanned)
		return err
	}
	counts := map[string]int{}
	for _, finding := range result.Findings {
		counts[finding.Level]++
		if _, err := fmt.Fprintf(writer, "%s %-6s %s:%d  %s\n", finding.RuleID, strings.ToUpper(finding.Level), finding.Path, finding.Line, finding.Title); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(writer, "  %s\n  Fix: %s\n", finding.Description, finding.Remediation); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(writer, "\n%d findings (%d high, %d medium, %d low) in %d files\n",
		len(result.Findings), counts["high"], counts["medium"], counts["low"], result.FilesScanned)
	return err
}
