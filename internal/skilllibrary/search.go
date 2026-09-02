package skilllibrary

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

func (s *Store) keyword(ctx context.Context, f Search) ([]Document, int, error) {
	where, args := conditions(f, 2)
	args = append([]any{f.Query}, args...)
	match := `($1='' OR strpos(lower(d.title||' '||d.path||' '||d.content||' '||d.metadata::text),lower($1))>0
 OR EXISTS(SELECT 1 FROM skill_library_text_chunks k WHERE k.document_id=d.id AND k.search_vector @@ websearch_to_tsquery('simple',$1)))`
	var total int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM skill_library_documents d WHERE `+where+` AND `+match, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}
	limit, offset := 60, 0
	if strings.TrimSpace(f.Query) == "" {
		limit = 25
		offset = (f.Page - 1) * 25
	}
	args = append(args, limit, offset)
	query := `SELECT ` + columns + ` FROM skill_library_documents d WHERE ` + where + ` AND ` + match + ` ORDER BY
 CASE WHEN lower(d.title)=lower($1) THEN 0 WHEN EXISTS(SELECT 1 FROM skill_library_document_cves cv WHERE cv.document_id=d.id AND cv.cve=upper($1)) THEN 1 ELSE 2 END,
 CASE WHEN $1='' THEN 0 ELSE COALESCE((SELECT MAX(ts_rank_cd(k.search_vector,websearch_to_tsquery('simple',$1))) FROM skill_library_text_chunks k WHERE k.document_id=d.id AND k.search_vector @@ websearch_to_tsquery('simple',$1)),0) END DESC,
 d.title,d.id LIMIT $` + fmt.Sprint(len(args)-1) + ` OFFSET $` + fmt.Sprint(len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Document{}
	for rows.Next() {
		d, e := scanDocument(rows)
		if e != nil {
			return nil, 0, e
		}
		d.Snippet = short(d.Content, 450)
		d.ExactCVE = exactCVE(d, f.Query)
		d.Content = ""
		d.Matches = []string{"keyword"}
		out = append(out, d)
	}
	return out, total, rows.Err()
}
func (s *Store) semantic(ctx context.Context, f Search, v []float32, key string) ([]Document, error) {
	if !validVector(v) {
		return nil, ErrInvalid
	}
	where, args := conditions(f, 3)
	raw, _ := json.Marshal(v)
	args = append([]any{string(raw), key}, args...)
	// Filtering is applied before the candidate limit, then several chunks of one
	// document collapse to its strongest evidence. Inactive/stale generations never match.
	query := `SELECT d.id,c.content,1-(c.embedding <=> $1::vector) AS similarity
 FROM skill_library_chunks c JOIN skill_library_documents d ON d.id=c.document_id
 WHERE ` + where + ` AND d.state='ready' AND c.model_key=$2 AND d.model_key=$2 AND c.index_hash=d.index_hash
 ORDER BY c.embedding <=> $1::vector LIMIT 240`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	type hit struct {
		id, text string
		score    float64
	}
	hits := []hit{}
	seen := map[string]bool{}
	for rows.Next() {
		var h hit
		if err = rows.Scan(&h.id, &h.text, &h.score); err != nil {
			rows.Close()
			return nil, err
		}
		if h.score >= 0.35 && !seen[h.id] {
			hits = append(hits, h)
			seen[h.id] = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	out := []Document{}
	for _, h := range hits {
		d, e := s.Get(ctx, h.id)
		if e != nil {
			return nil, e
		}
		d.ExactCVE = exactCVE(d, f.Query)
		d.Content = ""
		d.Snippet = short(h.text, 450)
		d.Score = h.score
		d.Matches = []string{"semantic"}
		out = append(out, d)
		if len(out) >= 60 {
			break
		}
	}
	return out, nil
}
func fuse(lexical, semantic []Document, query string) []Document {
	items := map[string]Document{}
	scores := map[string]float64{}
	for group, list := range [][]Document{lexical, semantic} {
		for i, d := range list {
			scores[d.ID] += 1 / float64(60+i+1)
			if old, ok := items[d.ID]; ok {
				old.Matches = append(old.Matches, d.Matches...)
				if group == 1 {
					old.Snippet = d.Snippet
				}
				items[d.ID] = old
			} else {
				items[d.ID] = d
			}
		}
	}
	// Identifiers are exact evidence, not a semantic similarity claim.
	if cveRE.FindString(strings.ToUpper(query)) == strings.ToUpper(query) && query != "" {
		for id, d := range items {
			if d.ExactCVE {
				scores[id] += 1
				continue
			}
			for _, cve := range append(append([]string{}, d.Metadata.CVEs...), d.Metadata.DetectedCVEs...) {
				if strings.EqualFold(cve, query) {
					scores[id] += 1
					break
				}
			}
		}
	}
	out := []Document{}
	for id, d := range items {
		d.Score = scores[id]
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score == out[j].Score {
			return out[i].ID < out[j].ID
		}
		return out[i].Score > out[j].Score
	})
	return out
}
func (s *Service) Search(ctx context.Context, f Search) (SearchResult, error) {
	out := SearchResult{Items: []Document{}, Mode: "keyword"}
	if err := f.Validate(); err != nil {
		return out, err
	}
	f.Query = strings.TrimSpace(f.Query)
	lex, total, err := s.store.keyword(ctx, f)
	if err != nil {
		return out, err
	}
	out.Items = lex
	out.Total = total
	if f.Query == "" {
		return out, nil
	}
	queryCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	vectors, err := s.embed.Embed(queryCtx, []string{f.Query})
	if err != nil {
		out.Warning = "本地向量服务暂不可用，本次仅返回关键词结果。"
		out.Total = len(lex)
		out.Items = pageItems(lex, f.Page)
		return out, nil
	}
	semantic, err := s.store.semantic(ctx, f, vectors[0], s.embed.Key())
	if err != nil {
		return out, err
	}
	out.Items = fuse(lex, semantic, f.Query)
	out.Mode = "hybrid"
	out.Total = len(out.Items)
	out.Items = pageItems(out.Items, f.Page)
	return out, nil
}

func pageItems(items []Document, page int) []Document {
	start := (page - 1) * 25
	if start >= len(items) {
		return []Document{}
	}
	end := start + 25
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}
