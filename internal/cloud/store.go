package cloud

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")

type Store struct{ db *sql.DB }

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("configure database: %w", err)
	}
	store := &Store{db: db}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, github_id INTEGER NOT NULL UNIQUE, login TEXT NOT NULL,
 email TEXT NOT NULL DEFAULT '', avatar_url TEXT NOT NULL DEFAULT '', plan TEXT NOT NULL DEFAULT 'free',
 stripe_customer_id TEXT NOT NULL DEFAULT '', created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS projects (
 id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 name TEXT NOT NULL, slug TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(owner_id, slug)
);
CREATE TABLE IF NOT EXISTS api_keys (
 id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 name TEXT NOT NULL, prefix TEXT NOT NULL, key_hash BLOB NOT NULL UNIQUE,
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, last_used_at DATETIME
);
CREATE TABLE IF NOT EXISTS scans (
 id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 commit_sha TEXT NOT NULL DEFAULT '', branch TEXT NOT NULL DEFAULT '', files_scanned INTEGER NOT NULL,
 high_count INTEGER NOT NULL, medium_count INTEGER NOT NULL, low_count INTEGER NOT NULL,
 findings_json TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS scans_project_created ON scans(project_id, created_at DESC);
`)
	if err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}
	return nil
}

func (s *Store) UpsertUser(ctx context.Context, githubID int64, login, email, avatar string) (User, error) {
	_, err := s.db.ExecContext(ctx, `INSERT INTO users(github_id,login,email,avatar_url) VALUES(?,?,?,?)
ON CONFLICT(github_id) DO UPDATE SET login=excluded.login,email=excluded.email,avatar_url=excluded.avatar_url`, githubID, login, email, avatar)
	if err != nil {
		return User{}, err
	}
	return s.UserByGitHubID(ctx, githubID)
}

func (s *Store) UserByGitHubID(ctx context.Context, githubID int64) (User, error) {
	var u User
	err := s.db.QueryRowContext(ctx, `SELECT id,github_id,login,email,avatar_url,plan,stripe_customer_id FROM users WHERE github_id=?`, githubID).
		Scan(&u.ID, &u.GitHubID, &u.Login, &u.Email, &u.AvatarURL, &u.Plan, &u.StripeCustomerID)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	var u User
	err := s.db.QueryRowContext(ctx, `SELECT id,github_id,login,email,avatar_url,plan,stripe_customer_id FROM users WHERE id=?`, id).
		Scan(&u.ID, &u.GitHubID, &u.Login, &u.Email, &u.AvatarURL, &u.Plan, &u.StripeCustomerID)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func (s *Store) CreateProject(ctx context.Context, ownerID int64, name, slug string) (Project, error) {
	result, err := s.db.ExecContext(ctx, `INSERT INTO projects(owner_id,name,slug) VALUES(?,?,?)`, ownerID, name, slug)
	if err != nil {
		return Project{}, err
	}
	id, _ := result.LastInsertId()
	var p Project
	err = s.db.QueryRowContext(ctx, `SELECT id,name,slug,created_at FROM projects WHERE id=?`, id).Scan(&p.ID, &p.Name, &p.Slug, &p.CreatedAt)
	return p, err
}

func (s *Store) Projects(ctx context.Context, ownerID int64) ([]Project, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,slug,created_at FROM projects WHERE owner_id=? ORDER BY created_at`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	projects := []Project{}
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.Name, &p.Slug, &p.CreatedAt); err != nil {
			return nil, err
		}
		projects = append(projects, p)
	}
	return projects, rows.Err()
}

func (s *Store) ProjectOwned(ctx context.Context, projectID, ownerID int64) (Project, error) {
	var p Project
	err := s.db.QueryRowContext(ctx, `SELECT id,name,slug,created_at FROM projects WHERE id=? AND owner_id=?`, projectID, ownerID).Scan(&p.ID, &p.Name, &p.Slug, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	return p, err
}

func (s *Store) ProjectCount(ctx context.Context, ownerID int64) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM projects WHERE owner_id=?`, ownerID).Scan(&count)
	return count, err
}

func (s *Store) InsertAPIKey(ctx context.Context, projectID int64, name, prefix string, hash []byte) (APIKey, error) {
	result, err := s.db.ExecContext(ctx, `INSERT INTO api_keys(project_id,name,prefix,key_hash) VALUES(?,?,?,?)`, projectID, name, prefix, hash)
	if err != nil {
		return APIKey{}, err
	}
	id, _ := result.LastInsertId()
	var key APIKey
	err = s.db.QueryRowContext(ctx, `SELECT id,name,prefix,created_at,last_used_at FROM api_keys WHERE id=?`, id).Scan(&key.ID, &key.Name, &key.Prefix, &key.CreatedAt, &key.LastUsed)
	return key, err
}

func (s *Store) APIKeys(ctx context.Context, projectID, ownerID int64) ([]APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT k.id,k.name,k.prefix,k.created_at,k.last_used_at FROM api_keys k JOIN projects p ON p.id=k.project_id WHERE k.project_id=? AND p.owner_id=? ORDER BY k.created_at`, projectID, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := []APIKey{}
	for rows.Next() {
		var key APIKey
		if err := rows.Scan(&key.ID, &key.Name, &key.Prefix, &key.CreatedAt, &key.LastUsed); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *Store) DeleteAPIKey(ctx context.Context, keyID, projectID, ownerID int64) (bool, error) {
	result, err := s.db.ExecContext(ctx, `DELETE FROM api_keys WHERE id=? AND project_id=? AND EXISTS(SELECT 1 FROM projects WHERE id=? AND owner_id=?)`, keyID, projectID, projectID, ownerID)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}

func (s *Store) ProjectByAPIKey(ctx context.Context, hash []byte) (Project, User, error) {
	var p Project
	var u User
	var keyID int64
	err := s.db.QueryRowContext(ctx, `SELECT p.id,p.name,p.slug,p.created_at,u.id,u.github_id,u.login,u.email,u.avatar_url,u.plan,u.stripe_customer_id,k.id
FROM api_keys k JOIN projects p ON p.id=k.project_id JOIN users u ON u.id=p.owner_id WHERE k.key_hash=?`, hash).
		Scan(&p.ID, &p.Name, &p.Slug, &p.CreatedAt, &u.ID, &u.GitHubID, &u.Login, &u.Email, &u.AvatarURL, &u.Plan, &u.StripeCustomerID, &keyID)
	if errors.Is(err, sql.ErrNoRows) {
		return Project{}, User{}, ErrNotFound
	}
	if err != nil {
		return Project{}, User{}, err
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE api_keys SET last_used_at=CURRENT_TIMESTAMP WHERE id=?`, keyID)
	return p, u, nil
}

func (s *Store) InsertScan(ctx context.Context, projectID int64, upload ScanUpload) (Scan, error) {
	counts := map[string]int{}
	for _, f := range upload.Findings {
		counts[strings.ToLower(f.Severity)]++
	}
	data, err := json.Marshal(upload.Findings)
	if err != nil {
		return Scan{}, err
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO scans(project_id,commit_sha,branch,files_scanned,high_count,medium_count,low_count,findings_json) VALUES(?,?,?,?,?,?,?,?)`, projectID, upload.CommitSHA, upload.Branch, upload.FilesScanned, counts["high"], counts["medium"], counts["low"], string(data))
	if err != nil {
		return Scan{}, err
	}
	id, _ := result.LastInsertId()
	return s.ScanByID(ctx, id)
}

func (s *Store) ScanByID(ctx context.Context, id int64) (Scan, error) {
	var scan Scan
	err := s.db.QueryRowContext(ctx, `SELECT id,project_id,commit_sha,branch,files_scanned,high_count,medium_count,low_count,findings_json,created_at FROM scans WHERE id=?`, id).
		Scan(&scan.ID, &scan.ProjectID, &scan.CommitSHA, &scan.Branch, &scan.FilesScanned, &scan.High, &scan.Medium, &scan.Low, &scan.FindingsJSON, &scan.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Scan{}, ErrNotFound
	}
	return scan, err
}

func (s *Store) Scans(ctx context.Context, ownerID int64, since time.Time, limit int) ([]Scan, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT s.id,s.project_id,s.commit_sha,s.branch,s.files_scanned,s.high_count,s.medium_count,s.low_count,s.created_at FROM scans s JOIN projects p ON p.id=s.project_id WHERE p.owner_id=? AND s.created_at>=? ORDER BY s.created_at DESC LIMIT ?`, ownerID, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	scans := []Scan{}
	for rows.Next() {
		var x Scan
		if err := rows.Scan(&x.ID, &x.ProjectID, &x.CommitSHA, &x.Branch, &x.FilesScanned, &x.High, &x.Medium, &x.Low, &x.CreatedAt); err != nil {
			return nil, err
		}
		scans = append(scans, x)
	}
	return scans, rows.Err()
}

func (s *Store) ScansSinceUser(ctx context.Context, ownerID int64, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans s JOIN projects p ON p.id=s.project_id WHERE p.owner_id=? AND s.created_at>=?`, ownerID, since).Scan(&n)
	return n, err
}

func (s *Store) SetBilling(ctx context.Context, userID int64, plan, customerID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET plan=?,stripe_customer_id=CASE WHEN ?='' THEN stripe_customer_id ELSE ? END WHERE id=?`, plan, customerID, customerID, userID)
	return err
}
func (s *Store) UserByStripeCustomer(ctx context.Context, customer string) (User, error) {
	var u User
	err := s.db.QueryRowContext(ctx, `SELECT id,github_id,login,email,avatar_url,plan,stripe_customer_id FROM users WHERE stripe_customer_id=?`, customer).Scan(&u.ID, &u.GitHubID, &u.Login, &u.Email, &u.AvatarURL, &u.Plan, &u.StripeCustomerID)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}
