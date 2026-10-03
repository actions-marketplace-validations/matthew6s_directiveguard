package scanner

import "regexp"

type rule struct {
	id          string
	severity    Severity
	title       string
	description string
	remediation string
	pattern     *regexp.Regexp
	exclude     *regexp.Regexp
	requires    *regexp.Regexp
}

var instructionRules = []rule{
	{
		id: "ASI001", severity: SeverityHigh, title: "Remote content is piped to a shell",
		description: "Agent instructions download remote content and execute it directly. A compromised server or redirected URL can execute arbitrary code.",
		remediation: "Download to a file, verify a pinned checksum or signature, inspect it, and then execute it.",
		pattern:     regexp.MustCompile(`(?i)(curl|wget)\b[^|\n]{0,300}\|\s*(ba)?sh\b`),
	},
	{
		id: "ASI002", severity: SeverityHigh, title: "Instructions request sensitive credentials",
		description: "Agent instructions direct the agent to read likely credential material outside the repository.",
		remediation: "Remove the instruction and provide narrowly scoped credentials through an approved secret store.",
		pattern:     regexp.MustCompile(`(?i)(read|open|print|cat|copy|upload|send|exfiltrat)[^\n]{0,100}(~/?\.ssh|~/?\.aws|~/?\.gnupg|credentials|id_rsa|github[_ -]?token)`),
	},
	{
		id: "ASI003", severity: SeverityMedium, title: "Instruction attempts to override governing rules",
		description: "Prompt-injection language asks an agent to disregard instructions or security controls.",
		remediation: "Remove override language and express the required task without bypassing higher-priority controls.",
		pattern:     regexp.MustCompile(`(?i)(ignore|disregard|override|bypass).{0,40}(previous|prior|system|developer|security).{0,30}(instruction|prompt|rule|control)`),
	},
	{
		id: "ASI004", severity: SeverityMedium, title: "Destructive recursive deletion",
		description: "Agent instructions contain a broad recursive deletion command that could destroy data if paths resolve unexpectedly.",
		remediation: "Use an explicit validated path and a recoverable deletion mechanism.",
		pattern:     regexp.MustCompile(`(?i)\brm\s+(?:-[a-z]*r[a-z]*f|-\-[^\n]*recursive)[^\n]*(?:\s/\s|\$HOME|~/|\$\{?HOME)`),
	},
}

var workflowRules = []rule{
	{
		id: "ASW001", severity: SeverityHigh, title: "Untrusted event data is interpolated into a shell command",
		description: "A workflow places attacker-controlled issue, comment, PR, or commit text directly in a run block.",
		remediation: "Pass the value through an environment variable and treat it as data, or use a purpose-built action with strict input handling.",
		pattern:     regexp.MustCompile(`(?i)^\s*(?:-\s*)?run\s*:[^\n]*\$\{\{\s*github\.event\.(issue\.body|comment\.body|pull_request\.(body|title)|head_commit\.message)`),
	},
	{
		id: "ASW002", severity: SeverityHigh, title: "Workflow grants write-all permissions",
		description: "The workflow grants write access to every available GitHub token permission.",
		remediation: "Declare only the specific read or write permissions required by each job.",
		pattern:     regexp.MustCompile(`(?i)^\s*permissions\s*:\s*write-all\s*(?:#.*)?$`),
	},
	{
		id: "ASW003", severity: SeverityHigh, title: "pull_request_target workflow checks out pull-request code",
		description: "Checking out an untrusted pull-request ref in a privileged pull_request_target workflow can expose repository secrets or write tokens.",
		remediation: "Use pull_request with read-only permissions, or avoid executing and checking out untrusted pull-request code.",
		pattern:     regexp.MustCompile(`(?i)^\s*ref\s*:\s*["']?\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)\s*\}\}`),
		requires:    regexp.MustCompile(`(?m)^\s*(?:on\s*:\s*\[[^]]*)?pull_request_target\b`),
	},
	{
		id: "ASW004", severity: SeverityMedium, title: "Action uses a mutable version",
		description: "An action referenced by a branch or floating tag can change without review.",
		remediation: "Pin actions to a full commit SHA and use a comment to record the release version.",
		pattern:     regexp.MustCompile(`(?i)^\s*-?\s*uses:\s*[a-z0-9_.-]+/[a-z0-9_.-]+@(main|master|latest|v\d+)\s*(?:#.*)?$`),
	},
}

var mcpRules = []rule{
	{
		id: "ASM001", severity: SeverityHigh, title: "MCP server uses an insecure remote URL",
		description: "The MCP configuration connects over unencrypted HTTP, allowing server responses and credentials to be intercepted or modified.",
		remediation: "Use HTTPS with a trusted server and certificate.",
		pattern:     regexp.MustCompile(`(?i)"(?:url|endpoint)"\s*:\s*"http://`),
	},
	{
		id: "ASM002", severity: SeverityMedium, title: "MCP package is installed without an exact version",
		description: "The configuration lets npx install a package whose contents can change between runs.",
		remediation: "Pin the package to an exact reviewed version, such as package-name@1.2.3.",
		pattern:     regexp.MustCompile(`(?i)"(?:args|command)"\s*:[^\n]*(?:-y|--yes)[^\n]*"(?:@[^/"\s]+/)?[^@"\s]+"(?:\s*[,\]])`),
	},
	{
		id: "ASM003", severity: SeverityHigh, title: "Credential appears embedded in MCP configuration",
		description: "The MCP configuration appears to contain a literal token, API key, or password.",
		remediation: "Remove the value, rotate it, and load a narrowly scoped secret from the environment or a secret manager.",
		pattern:     regexp.MustCompile(`(?i)"[^"\n]*(token|api[_-]?key|password|secret)[^"\n]*"\s*:\s*"[^"\n]{8,}"`),
		exclude:     regexp.MustCompile(`(?i)"\s*:\s*"(\$\{|\$[A-Z_]+|<|REPLACE|YOUR_)`),
	},
}

func rulesFor(kind fileKind) []rule {
	switch kind {
	case fileInstructions:
		return instructionRules
	case fileWorkflow:
		return workflowRules
	case fileMCP:
		return mcpRules
	default:
		return nil
	}
}
