package cloud

import "time"

type User struct {
	ID               int64  `json:"id"`
	GitHubID         int64  `json:"github_id"`
	Login            string `json:"login"`
	Email            string `json:"email,omitempty"`
	AvatarURL        string `json:"avatar_url,omitempty"`
	Plan             string `json:"plan"`
	StripeCustomerID string `json:"-"`
}

type Project struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
}

type APIKey struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	Prefix    string     `json:"prefix"`
	CreatedAt time.Time  `json:"created_at"`
	LastUsed  *time.Time `json:"last_used_at,omitempty"`
}

type Scan struct {
	ID           int64     `json:"id"`
	ProjectID    int64     `json:"project_id"`
	CommitSHA    string    `json:"commit_sha,omitempty"`
	Branch       string    `json:"branch,omitempty"`
	FilesScanned int       `json:"files_scanned"`
	High         int       `json:"high"`
	Medium       int       `json:"medium"`
	Low          int       `json:"low"`
	FindingsJSON string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

type ScanUpload struct {
	CommitSHA    string        `json:"commit_sha,omitempty"`
	Branch       string        `json:"branch,omitempty"`
	FilesScanned int           `json:"files_scanned"`
	Findings     []ScanFinding `json:"findings"`
}

type ScanFinding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Path        string `json:"path"`
	Line        int    `json:"line"`
	Remediation string `json:"remediation,omitempty"`
}
