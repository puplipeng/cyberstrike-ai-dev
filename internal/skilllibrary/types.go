// Package skilllibrary indexes shared skill packages and PoC reference material.
// Source files remain authoritative. This package never executes their contents.
package skilllibrary

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const Dimension = 1024
const MaxFileBytes = 1 << 20

var ErrConflict = errors.New("source or metadata changed; rescan and reload before saving")
var ErrBusy = errors.New("index job already running")
var ErrInvalid = errors.New("invalid library request")
var ErrEmbeddingUnavailable = errors.New("embedding service unavailable")
var cveRE = regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]{4,19}\b`)
var idRE = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Metadata struct {
	DetectedCVEs  []string `json:"detected_cves"`
	CVEs          []string `json:"cves"`
	Products      []string `json:"products"`
	Versions      string   `json:"versions"`
	Prerequisites string   `json:"prerequisites"`
	License       string   `json:"license"`
	SourceURL     string   `json:"source_url"`
	Notes         string   `json:"notes"`
}
type Document struct {
	DetectedCVECount int       `json:"detected_cve_count"`
	ExactCVE         bool      `json:"-"`
	ID               string    `json:"id"`
	Root             string    `json:"root"`
	Path             string    `json:"path"`
	Kind             string    `json:"kind"`
	Title            string    `json:"title"`
	Skill            string    `json:"skill"`
	Hash             string    `json:"hash"`
	Content          string    `json:"content,omitempty"`
	Metadata         Metadata  `json:"metadata"`
	Review           string    `json:"review"`
	State            string    `json:"state"`
	Error            string    `json:"error,omitempty"`
	Revision         int64     `json:"revision"`
	Missing          bool      `json:"missing"`
	Updated          time.Time `json:"updated"`
	IndexHash        string    `json:"-"`
	ModelKey         string    `json:"-"`
	Snippet          string    `json:"snippet,omitempty"`
	Score            float64   `json:"score,omitempty"`
	Matches          []string  `json:"matches,omitempty"`
}
type Link struct {
	SkillID       string `json:"skill_id"`
	ResourceID    string `json:"resource_id"`
	SkillTitle    string `json:"skill_title"`
	ResourceTitle string `json:"resource_title"`
	Source        string `json:"source"`
	Note          string `json:"note"`
}
type Search struct {
	Query, Kind, Review, CVE, Product string
	Page                              int
}
type SearchResult struct {
	Items   []Document `json:"items"`
	Total   int        `json:"total"`
	Mode    string     `json:"mode"`
	Warning string     `json:"warning,omitempty"`
}
type Status struct {
	Running        bool       `json:"running"`
	Phase          string     `json:"phase"`
	Total          int        `json:"total"`
	Ready          int        `json:"ready"`
	Pending        int        `json:"pending"`
	Failed         int        `json:"failed"`
	Missing        int        `json:"missing"`
	Approved       int        `json:"approved"`
	AwaitingReview int        `json:"awaiting_review"`
	Disabled       int        `json:"disabled"`
	Available      int        `json:"available"`
	Chunks         int        `json:"chunks"`
	Skipped        int        `json:"skipped"`
	LastRun        *time.Time `json:"last_run"`
	LastError      string     `json:"last_error"`
	Model          string     `json:"model"`
	Dimension      int        `json:"dimension"`
}

func validID(id string) bool { return idRE.MatchString(id) }
func digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func indexHash(d Document) string {
	m, _ := json.Marshal(d.Metadata)
	return digest("chunks-v1\n" + d.Hash + "\n" + d.Title + "\n" + string(m))
}
func short(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
func (s Search) Validate() error {
	if !utf8.ValidString(s.Query) || len([]rune(s.Query)) > 500 || s.Page < 1 || s.Page > 10000 || strings.ContainsRune(s.Query, 0) {
		return ErrInvalid
	}
	if s.Kind != "" && s.Kind != "skill" && s.Kind != "reference" && s.Kind != "poc" {
		return ErrInvalid
	}
	if s.Review != "" && s.Review != "all" && s.Review != "unreviewed" && s.Review != "reviewed" && s.Review != "rejected" {
		return ErrInvalid
	}
	if s.CVE != "" && (!cveRE.MatchString(s.CVE) || cveRE.FindString(s.CVE) != s.CVE) {
		return ErrInvalid
	}
	if len(s.Product) > 200 || strings.ContainsRune(s.Product, 0) {
		return ErrInvalid
	}
	return nil
}
func (m *Metadata) Validate() error {
	b, _ := json.Marshal(m)
	if len(b) > 16000 || len(m.CVEs) > 50 || len(m.Products) > 30 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	ids := []string{}
	for _, id := range m.CVEs {
		id = strings.ToUpper(strings.TrimSpace(id))
		if cveRE.FindString(id) != id || id == "" {
			return ErrInvalid
		}
		if !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	m.CVEs = ids
	for _, p := range m.Products {
		if strings.TrimSpace(p) == "" || len(p) > 200 || strings.ContainsRune(p, 0) {
			return ErrInvalid
		}
	}
	for _, v := range []string{m.Versions, m.Prerequisites, m.License, m.Notes} {
		if !utf8.ValidString(v) || strings.ContainsRune(v, 0) || len(v) > 6000 {
			return ErrInvalid
		}
	}
	if m.SourceURL != "" {
		u, e := url.Parse(m.SourceURL)
		if e != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || len(m.SourceURL) > 2000 {
			return ErrInvalid
		}
	}
	return nil
}
