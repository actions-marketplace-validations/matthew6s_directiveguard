package scanner

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const maxFileSize = 2 << 20

var skippedDirectories = map[string]bool{
	".git": true, ".hg": true, ".svn": true, "node_modules": true,
	"vendor": true, "dist": true, "build": true, ".next": true,
}

func Scan(root string) (Result, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return Result{}, fmt.Errorf("resolve root: %w", err)
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return Result{}, fmt.Errorf("open %s: %w", root, err)
	}
	if !info.IsDir() {
		return Result{}, fmt.Errorf("%s is not a directory", root)
	}
	result := Result{Root: absRoot, Findings: []Finding{}}
	err = filepath.WalkDir(absRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, fs.ErrPermission) {
				return nil
			}
			return walkErr
		}
		if entry.IsDir() {
			if path != absRoot && skippedDirectories[entry.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		// Never follow repository-controlled symlinks. Besides escaping the scan
		// root, a symlinked config could cause local credentials to enter a report.
		if entry.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		kind := classify(path, absRoot)
		if kind == fileUnknown {
			return nil
		}
		fileInfo, err := entry.Info()
		if err != nil || fileInfo.Size() > maxFileSize {
			return nil
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				return nil
			}
			return err
		}
		if strings.IndexByte(string(contents), 0) >= 0 {
			return nil
		}
		relative, err := filepath.Rel(absRoot, path)
		if err != nil {
			return err
		}
		result.FilesScanned++
		result.Findings = append(result.Findings, inspect(relative, string(contents), kind)...)
		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("scan repository: %w", err)
	}
	sort.Slice(result.Findings, func(i, j int) bool {
		if result.Findings[i].Severity != result.Findings[j].Severity {
			return result.Findings[i].Severity > result.Findings[j].Severity
		}
		if result.Findings[i].Path != result.Findings[j].Path {
			return result.Findings[i].Path < result.Findings[j].Path
		}
		return result.Findings[i].Line < result.Findings[j].Line
	})
	return result, nil
}

type fileKind int

const (
	fileUnknown fileKind = iota
	fileInstructions
	fileWorkflow
	fileMCP
)

func classify(path, root string) fileKind {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return fileUnknown
	}
	slashPath := filepath.ToSlash(relative)
	base := strings.ToLower(filepath.Base(path))
	if strings.HasPrefix(slashPath, ".github/workflows/") &&
		(strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")) {
		return fileWorkflow
	}
	if base == "agents.md" || base == "claude.md" || base == "copilot-instructions.md" ||
		base == ".cursorrules" || strings.HasSuffix(base, ".instructions.md") {
		return fileInstructions
	}
	if base == ".mcp.json" || base == "mcp.json" || base == "mcp-config.json" ||
		base == "claude_desktop_config.json" {
		return fileMCP
	}
	return fileUnknown
}

func inspect(path, contents string, kind fileKind) []Finding {
	var findings []Finding
	scanner := bufio.NewScanner(strings.NewReader(contents))
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, maxFileSize)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		for _, rule := range rulesFor(kind) {
			if rule.pattern.MatchString(line) &&
				(rule.exclude == nil || !rule.exclude.MatchString(line)) &&
				(rule.requires == nil || rule.requires.MatchString(contents)) {
				findings = append(findings, Finding{
					RuleID: rule.id, Severity: rule.severity, Level: rule.severity.String(),
					Title: rule.title, Description: rule.description, Path: filepath.ToSlash(path),
					Line: lineNumber, Snippet: safeSnippet(rule.id, line), Remediation: rule.remediation,
				})
			}
		}
	}
	return deduplicate(findings)
}

func safeSnippet(ruleID, line string) string {
	// Never copy a suspected credential into JSON or SARIF artifacts.
	if ruleID == "ASM003" {
		return "[suspected credential redacted]"
	}
	line = strings.TrimSpace(line)
	if len(line) > 180 {
		line = line[:177] + "..."
	}
	return line
}

func deduplicate(findings []Finding) []Finding {
	seen := make(map[string]bool)
	output := findings[:0]
	for _, finding := range findings {
		key := fmt.Sprintf("%s:%d:%s", finding.Path, finding.Line, finding.RuleID)
		if !seen[key] {
			seen[key] = true
			output = append(output, finding)
		}
	}
	return output
}
