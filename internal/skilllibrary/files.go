package skilllibrary

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"cyberstrike-ai/internal/skillpackage"
)

type Source struct{ Name, Path, Kind string }

var secretRE = regexp.MustCompile(`(?i)(sk-[a-z0-9_-]{24,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)`)
var allowedExt = map[string]bool{".md": true, ".txt": true, ".py": true, ".go": true, ".js": true, ".ts": true, ".sh": true, ".ps1": true, ".yaml": true, ".yml": true, ".json": true, ".http": true, ".xml": true, ".rb": true, ".c": true, ".java": true}

// Read within a descriptor-based root; paths in HTTP requests are never passed here.
func readSource(source Source, relative string) (string, error) {
	if !fs.ValidPath(relative) || strings.ContainsAny(relative, "\\:\x00") {
		return "", ErrInvalid
	}
	r, err := os.OpenRoot(source.Path)
	if err != nil {
		return "", err
	}
	defer r.Close()
	f, err := r.Open(filepath.FromSlash(relative))
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() || st.Size() > MaxFileBytes {
		return "", ErrInvalid
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return "", err
	}
	if len(b) > MaxFileBytes || !utf8.Valid(b) || strings.ContainsRune(string(b), 0) {
		return "", ErrInvalid
	}
	return string(b), nil
}
func scanSources(sources []Source) ([]Document, int, error) {
	docs := []Document{}
	skipped := 0
	for _, source := range sources {
		r, err := os.OpenRoot(source.Path)
		if err != nil {
			return nil, skipped, fmt.Errorf("open source %s: %w", source.Name, err)
		}
		err = fs.WalkDir(r.FS(), ".", func(rel string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if rel == "." {
				return nil
			}
			if strings.HasPrefix(entry.Name(), ".") || strings.Count(rel, "/") > 16 {
				if entry.IsDir() {
					return fs.SkipDir
				}
				skipped++
				return nil
			}
			if entry.Type()&fs.ModeSymlink != 0 {
				skipped++
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			if len(docs) >= 10000 {
				return fmt.Errorf("source exceeds 10000 files")
			}
			if !allowedExt[strings.ToLower(path.Ext(rel))] {
				skipped++
				return nil
			}
			content, e := readSource(source, rel)
			if e != nil {
				if e == ErrInvalid {
					skipped++
					return nil
				}
				return e
			}
			if secretRE.MatchString(content) {
				skipped++
				return nil
			}
			d := Document{ID: digest(source.Name + "\n" + rel), Root: source.Name, Path: rel, Kind: source.Kind, Title: path.Base(rel), Content: content, Hash: digest(content), Review: "unreviewed"}
			d.Metadata.CVEs = []string{}
			d.Metadata.Products = []string{}
			detected := detectCVEs(content)
			d.DetectedCVECount = len(detected)
			// Only the UI preview is capped; the separate CVE index stores all IDs.
			d.Metadata.DetectedCVEs = detected[:min(50, len(detected))]
			if source.Name == "skills" {
				parts := strings.Split(rel, "/")
				if len(parts) > 1 {
					d.Skill = parts[0]
				}
				if len(parts) == 2 && parts[1] == "SKILL.md" {
					manifest, _, e := skillpackage.ParseSkillMD([]byte(content))
					if e != nil {
						return fmt.Errorf("invalid SKILL.md: %s", rel)
					}
					d.Kind = "skill"
					d.Title = manifest.Name
					d.Metadata.License = manifest.License
				} else {
					d.Kind = "reference"
				}
			}
			docs = append(docs, d)
			return nil
		})
		r.Close()
		if err != nil {
			return nil, skipped, err
		}
	}
	return docs, skipped, nil
}

func detectCVEs(content string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, match := range cveRE.FindAllString(content, -1) {
		id := strings.ToUpper(match)
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func exactCVE(d Document, query string) bool {
	if query == "" || cveRE.FindString(query) != query {
		return false
	}
	for _, id := range d.Metadata.CVEs {
		if strings.EqualFold(id, query) {
			return true
		}
	}
	for _, loc := range cveRE.FindAllStringIndex(d.Content, -1) {
		if strings.EqualFold(d.Content[loc[0]:loc[1]], query) {
			return true
		}
	}
	return false
}

// Chunks are search evidence only. Execution must never consume a partial chunk.
func chunks(content string) []string {
	r := []rune(content)
	out := []string{}
	for start := 0; start < len(r); {
		end := start + 1600
		if end > len(r) {
			end = len(r)
		}
		if end < len(r) {
			for i := end; i > start+1000; i-- {
				if r[i-1] == '\n' {
					end = i
					break
				}
			}
		}
		if text := strings.TrimSpace(string(r[start:end])); text != "" {
			out = append(out, text)
		}
		if end == len(r) {
			break
		}
		start = end - 160
	}
	return out
}
