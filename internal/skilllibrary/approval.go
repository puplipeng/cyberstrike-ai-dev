package skilllibrary

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cyberstrike-ai/internal/skillpackage"
)

const approvalManifestVersion = 1

type approvalManifest struct {
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	Skills    []string  `json:"skills"`
}

// ApprovalManifestPath is shared by the review service and the Agent skill
// loader. Keeping the manifest outside skills_dir prevents it being indexed as
// source material.
func ApprovalManifestPath(skillsDir string) (string, error) {
	skillsDir = strings.TrimSpace(skillsDir)
	if skillsDir == "" {
		return "", fmt.Errorf("resolve skills approval manifest: empty skills directory")
	}
	abs, err := filepath.Abs(skillsDir)
	if err != nil {
		return "", fmt.Errorf("resolve skills approval manifest: %w", err)
	}
	return filepath.Join(filepath.Dir(abs), "data", "skill-library", "approved-skills.json"), nil
}

// LoadApprovedSkillNames returns found=false for installations that do not use
// the skill library. Once the manifest exists it is a fail-closed allowlist.
func LoadApprovedSkillNames(skillsDir string) (names map[string]struct{}, found bool, err error) {
	manifestPath, err := ApprovalManifestPath(skillsDir)
	if err != nil {
		return nil, false, err
	}
	data, err := os.ReadFile(manifestPath)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	if len(data) > 1<<20 {
		return nil, true, fmt.Errorf("skills approval manifest is too large")
	}
	var manifest approvalManifest
	if err = json.Unmarshal(data, &manifest); err != nil {
		return nil, true, fmt.Errorf("decode skills approval manifest: %w", err)
	}
	if manifest.Version != approvalManifestVersion {
		return nil, true, fmt.Errorf("unsupported skills approval manifest version %d", manifest.Version)
	}
	names = make(map[string]struct{}, len(manifest.Skills))
	for _, name := range manifest.Skills {
		name = strings.TrimSpace(name)
		if name == "" || len(name) > 200 {
			return nil, true, fmt.Errorf("invalid skill name in approval manifest")
		}
		names[name] = struct{}{}
	}
	return names, true, nil
}

func (s *Store) approvedSkillDocuments(ctx context.Context) ([]Document, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+columns+` FROM skill_library_documents
 WHERE root='skills' AND kind='skill' AND review='reviewed' AND NOT missing ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	docs := []Document{}
	for rows.Next() {
		d, scanErr := scanDocument(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		docs = append(docs, d)
	}
	return docs, rows.Err()
}

func (s *Service) syncApprovedSkills(ctx context.Context) error {
	skillsDir := ""
	for _, source := range s.sources {
		if source.Name == "skills" {
			skillsDir = source.Path
			break
		}
	}
	if skillsDir == "" {
		return nil
	}
	docs, err := s.store.approvedSkillDocuments(ctx)
	if err != nil {
		return err
	}
	seen := map[string]struct{}{}
	for _, doc := range docs {
		// A changed or removed source must not remain published during the gap
		// before the next background scan resets its database review state.
		if !s.SourceCurrent(doc) {
			continue
		}
		manifest, _, parseErr := skillpackage.ParseSkillMD([]byte(doc.Content))
		if parseErr != nil {
			return fmt.Errorf("parse approved skill %s: %w", doc.Path, parseErr)
		}
		seen[manifest.Name] = struct{}{}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	manifestPath, err := ApprovalManifestPath(skillsDir)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(manifestPath), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(approvalManifest{Version: approvalManifestVersion, UpdatedAt: time.Now().UTC(), Skills: names}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err = os.WriteFile(manifestPath, data, 0600); err != nil {
		return fmt.Errorf("write skills approval manifest: %w", err)
	}
	return nil
}
