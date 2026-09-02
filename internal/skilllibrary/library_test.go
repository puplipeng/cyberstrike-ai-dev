package skilllibrary

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/testutil/testpostgres"
	_ "github.com/jackc/pgx/v5/stdlib"
	"go.uber.org/zap"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("pgx", testpostgres.DSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err = db.Exec(`CREATE EXTENSION vector`); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func vectorAt(i int) []float32 { v := make([]float32, Dimension); v[i] = 1; return v }
func document(name, kind, content string) Document {
	return Document{ID: digest(name), Root: "skills", Path: name, Kind: kind, Skill: "demo", Title: name, Content: content, Hash: digest(content), Metadata: Metadata{CVEs: []string{}, DetectedCVEs: []string{}, Products: []string{}}, Review: "unreviewed"}
}

func approveAll(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.db.Exec(`UPDATE skill_library_documents SET review='reviewed' WHERE NOT missing`); err != nil {
		t.Fatal(err)
	}
}

type fakeEmbedder struct {
	fail  bool
	calls int
	key   string
}

func (e *fakeEmbedder) Key() string {
	if e.key != "" {
		return e.key
	}
	return "model-v1"
}
func (e *fakeEmbedder) Model() string { return "fixture" }
func (e *fakeEmbedder) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	e.calls++
	if e.fail {
		return nil, errors.New("offline")
	}
	out := [][]float32{}
	for range texts {
		out = append(out, vectorAt(0))
	}
	return out, nil
}

func TestScanSourceBoundariesClassificationAndSecrets(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "demo"), 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"demo/SKILL.md": "---\nname: demo\ndescription: Sample workflow\n---\nCVE-2021-44228", "demo/poc.py": "print('not executed')", "demo/.env": "SECRET=hidden", "demo/key.txt": "sk-" + strings.Repeat("a", 30)}
	for name, text := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	docs, skipped, err := scanSources([]Source{{Name: "skills", Path: root, Kind: "reference"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 2 || skipped != 2 {
		t.Fatalf("documents=%d skipped=%d", len(docs), skipped)
	}
	for _, d := range docs {
		if strings.HasSuffix(d.Path, ".py") && d.Kind != "reference" {
			t.Fatal("script automatically declared a PoC")
		}
		if d.Kind == "skill" && len(d.Metadata.DetectedCVEs) != 1 {
			t.Fatal("CVE not detected")
		}
	}
	for _, path := range []string{"../secret", "C:/secret", "demo\\..\\secret"} {
		if _, err = readSource(Source{Path: root}, path); err == nil {
			t.Fatalf("unsafe path %q", path)
		}
	}
	if _, _, err = scanSources([]Source{{Name: "missing", Path: filepath.Join(root, "missing")}}); err == nil {
		t.Fatal("missing source silently ignored")
	}
}
func TestChunkUnicodeAndEmbeddingValidation(t *testing.T) {
	text := strings.Repeat("中文检索与验证\n", 1000)
	parts := chunks(text)
	if len(parts) < 2 {
		t.Fatal("not chunked")
	}
	for _, p := range parts {
		if len([]rune(p)) > 1600 || strings.ContainsRune(p, '\ufffd') {
			t.Fatal("invalid Unicode chunk")
		}
	}
	if validVector(make([]float32, 1024)) || validVector(vectorAt(0)[:1023]) {
		t.Fatal("invalid vector accepted")
	}
	v := vectorAt(0)
	v[1] = float32(math.Inf(1))
	if validVector(v) {
		t.Fatal("nonfinite accepted")
	}
	for _, base := range []string{"https://remote.example", "http://localhost:80", "http://127.0.0.1:1/path", "http://user:pass@127.0.0.1:2"} {
		if _, err := NewLocalEmbedder(base, "bge-m3", ""); err == nil {
			t.Fatalf("untrusted embedding origin %s", base)
		}
	}
}
func TestLocalEmbeddingProtocolAndRedirect(t *testing.T) {
	redirect := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("unexpected credentials")
		}
		if redirect {
			http.Redirect(w, r, "http://example.invalid", 302)
			return
		}
		var request struct {
			Input    []string `json:"input"`
			Truncate bool     `json:"truncate"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.Truncate {
			t.Error("invalid request")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"embeddings": [][]float32{vectorAt(0)}})
	}))
	defer server.Close()
	e, err := NewLocalEmbedder(server.URL, "bge-m3", "")
	if err != nil {
		t.Fatal(err)
	}
	v, err := e.Embed(context.Background(), []string{"test"})
	if err != nil || len(v) != 1 {
		t.Fatalf("embedding %v", err)
	}
	redirect = true
	if _, err = e.Embed(context.Background(), []string{"test"}); err == nil {
		t.Fatal("redirect accepted")
	}
}
func TestStoreIndexAtomicityFiltersAndMetadata(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a := document("demo/SKILL.md", "skill", "Java logging assessment CVE-2021-44228")
	b := document("demo/reference.md", "reference", "Unrelated reference")
	a.Metadata.DetectedCVEs = []string{"CVE-2021-44228"}
	a.Metadata.Products = []string{"Log4j"}
	if err := s.saveScan(ctx, []Document{a, b}); err != nil {
		t.Fatal(err)
	}
	approveAll(t, s)
	a, _ = s.Get(ctx, a.ID)
	b, _ = s.Get(ctx, b.ID)
	if err := s.saveVectors(ctx, a, []string{a.Content}, [][]float32{vectorAt(0)}, "model-v1"); err != nil {
		t.Fatal(err)
	}
	if err := s.saveVectors(ctx, b, []string{b.Content}, [][]float32{vectorAt(1)}, "model-v1"); err != nil {
		t.Fatal(err)
	}
	for _, f := range []Search{{Query: "CVE-2021-44228", Page: 1}, {CVE: "CVE-2021-44228", Page: 1}, {Product: "Log4j", Page: 1}} {
		items, _, err := s.keyword(ctx, f)
		if err != nil || len(items) != 1 || items[0].ID != a.ID {
			t.Fatalf("filter %+v: %+v %v", f, items, err)
		}
	}
	for _, q := range []string{"' OR 1=1 --", "%"} {
		items, _, err := s.keyword(ctx, Search{Query: q, Page: 1})
		if err != nil || len(items) != 0 {
			t.Fatalf("literal query %q: %v", q, err)
		}
	}
	hits, err := s.semantic(ctx, Search{Page: 1}, vectorAt(0), "model-v1")
	if err != nil || len(hits) != 1 || hits[0].ID != a.ID {
		t.Fatalf("semantic %+v %v", hits, err)
	}
	if err = s.saveVectors(ctx, a, []string{"bad"}, [][]float32{make([]float32, 1024)}, "model-v1"); err == nil {
		t.Fatal("invalid vectors stored")
	}
	var old string
	s.db.QueryRow(`SELECT content FROM skill_library_chunks WHERE document_id=$1`, a.ID).Scan(&old)
	if old != a.Content {
		t.Fatal("failed replacement destroyed old vectors")
	}
	edit := Edit{Title: "Custom title", Kind: a.Kind, Review: "reviewed", Metadata: a.Metadata, Revision: a.Revision}
	if err = s.Edit(ctx, a.ID, "admin", edit); err != nil {
		t.Fatal(err)
	}
	if err = s.Edit(ctx, a.ID, "admin", edit); !errors.Is(err, ErrConflict) {
		t.Fatal("lost update accepted")
	}
	a.Content = "New source CVE-2024-12345"
	a.Hash = digest(a.Content)
	a.Metadata.DetectedCVEs = []string{"CVE-2024-12345"}
	if err = s.saveScan(ctx, []Document{a, b}); err != nil {
		t.Fatal(err)
	}
	fresh, _ := s.Get(ctx, a.ID)
	if fresh.Review != "unreviewed" || fresh.Title != "Custom title" || fresh.State != "pending" || fresh.Metadata.DetectedCVEs[0] != "CVE-2024-12345" {
		t.Fatalf("stale metadata %+v", fresh)
	}
	if err = s.saveVectors(ctx, a, []string{"obsolete"}, [][]float32{vectorAt(0)}, "model-v1"); !errors.Is(err, ErrConflict) {
		t.Fatal("stale generation committed")
	}
	if err = s.saveScan(ctx, []Document{b}); err != nil {
		t.Fatal(err)
	}
	fresh, _ = s.Get(ctx, a.ID)
	if !fresh.Missing {
		t.Fatal("removed source not archived")
	}
}
func TestLinksExplicitRelationshipsAndAudit(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a := document("demo/SKILL.md", "skill", "workflow")
	b := document("demo/script.py", "reference", "source")
	c := document("other.txt", "poc", "standalone")
	c.Root = "pocs"
	c.Skill = ""
	if err := s.saveScan(ctx, []Document{a, b, c}); err != nil {
		t.Fatal(err)
	}
	links, err := s.Links(ctx, b.ID)
	if err != nil || len(links) != 1 || links[0].Source != "package" {
		t.Fatalf("package links %v %v", links, err)
	}
	if err = s.Link(ctx, links[0], "admin", true); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("package link deleted manually")
	}
	l := Link{SkillID: a.ID, ResourceID: c.ID, Note: "requires review"}
	if err = s.Link(ctx, l, "admin", false); err != nil {
		t.Fatal(err)
	}
	if err = s.Link(ctx, l, "admin", false); err != nil {
		t.Fatal(err)
	}
	links, _ = s.Links(ctx, c.ID)
	if len(links) != 1 {
		t.Fatal("duplicate links")
	}
	if err = s.Link(ctx, l, "admin", true); err != nil {
		t.Fatal(err)
	}
	if err = s.Link(ctx, Link{SkillID: c.ID, ResourceID: b.ID}, "admin", false); !errors.Is(err, ErrInvalid) {
		t.Fatal("non-skill accepted as skill")
	}
	var count int
	s.db.QueryRow(`SELECT COUNT(*) FROM skill_library_audit`).Scan(&count)
	if count != 3 {
		t.Fatal("audit missing", count)
	}
}
func TestIncrementalIndexFallbackAndModelChanges(t *testing.T) {
	s := testStore(t)
	root := t.TempDir()
	file := filepath.Join(root, "note.md")
	os.WriteFile(file, []byte("Java 日志组件排查"), 0600)
	e := &fakeEmbedder{}
	service := NewService(s, e, []Source{{Name: "pocs", Path: root, Kind: "poc"}}, zap.NewNop())
	defer service.Close()
	ctx := context.Background()
	if err := service.run(ctx, false); err != nil {
		t.Fatal(err)
	}
	first := e.calls
	if err := service.run(ctx, false); err != nil || e.calls != first {
		t.Fatal("unchanged source embedded again", err)
	}
	e.key = "model-v2"
	if err := service.run(ctx, false); err != nil || e.calls <= first {
		t.Fatal("model change did not reindex", err)
	}
	e.fail = true
	e.key = "model-v3"
	result, err := service.Search(ctx, Search{Query: "Java", Review: "all", Page: 1})
	if err != nil || result.Mode != "keyword" || result.Warning == "" || len(result.Items) != 1 {
		t.Fatalf("fallback %v %v", result, err)
	}
	os.WriteFile(file, []byte("changed"), 0600)
	if err = service.run(ctx, false); err == nil {
		t.Fatal("embedding failure hidden")
	}
	status, _ := service.Status(ctx)
	if status.Failed != 1 || status.Pending != 0 || status.Ready != 0 {
		t.Fatalf("status %+v", status)
	}
	e.fail = false
	callsBeforeBackoff := e.calls
	if err = service.run(ctx, false); err != nil || e.calls != callsBeforeBackoff {
		t.Fatal("automatic retry ignored backoff", err)
	}
	if _, err = s.db.Exec(`UPDATE skill_library_documents SET retry_after=CURRENT_TIMESTAMP-INTERVAL '1 second'`); err != nil {
		t.Fatal(err)
	}
	if err = service.run(ctx, false); err != nil {
		t.Fatal(err)
	}
	status, _ = service.Status(ctx)
	if status.Ready != 1 || status.Failed != 0 {
		t.Fatalf("recovery %+v", status)
	}
	service.sources[0].Path = filepath.Join(root, "absent")
	if err = service.run(ctx, false); err == nil {
		t.Fatal("failed scan ignored")
	}
	status, _ = service.Status(ctx)
	if status.Missing != 0 {
		t.Fatal("failed scan archived records")
	}
}

func TestLargeFileKeywordIndexDoesNotAbortBatch(t *testing.T) {
	s := testStore(t)
	root := t.TempDir()
	var body strings.Builder
	for i := 0; i < 70000; i++ {
		fmt.Fprintf(&body, "symbol%06d ", i)
	}
	if body.Len() >= MaxFileBytes {
		t.Fatal("fixture exceeds allowed size")
	}
	for name, content := range map[string]string{"a-small.md": "small valid source", "z-large.md": body.String()} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	docs, skipped, err := scanSources([]Source{{Name: "pocs", Path: root, Kind: "poc"}})
	if err != nil || len(docs) != 2 || skipped != 0 {
		t.Fatalf("scan: %d %d %v", len(docs), skipped, err)
	}
	if err = s.saveScan(context.Background(), docs); err != nil {
		t.Fatal(err)
	}
	approveAll(t, s)
	for _, query := range []string{"symbol069999", "symbol000000 symbol000009", "small", "unmatched"} {
		_, total, err := s.keyword(context.Background(), Search{Query: query, Page: 1})
		want := 1
		if query == "unmatched" {
			want = 0
		}
		if err != nil || total != want {
			t.Fatalf("query=%q total=%d err=%v", query, total, err)
		}
	}
	var count, largest int
	if err = s.db.QueryRow(`SELECT COUNT(*),MAX(pg_column_size(search_vector)) FROM skill_library_text_chunks`).Scan(&count, &largest); err != nil {
		t.Fatal(err)
	}
	if count < 500 || largest >= 1<<20 {
		t.Fatalf("chunks=%d largest=%d", count, largest)
	}
	all, total, err := s.keyword(context.Background(), Search{Page: 1})
	if err != nil || total != 2 || len(all) != 2 {
		t.Fatalf("batch visibility: %d %v", total, err)
	}
}

type selectiveEmbedder struct {
	fakeEmbedder
	mode     string
	attempts int
}

func (e *selectiveEmbedder) Embed(ctx context.Context, input []string) ([][]float32, error) {
	e.attempts++
	if e.mode == "outage" {
		return nil, ErrEmbeddingUnavailable
	}
	for _, text := range input {
		if e.mode == "partial" && strings.Contains(text, "BROKEN-FIXTURE") {
			return nil, errors.New("fixture rejected")
		}
	}
	return e.fakeEmbedder.Embed(ctx, input)
}

func TestFailedDocumentsDoNotStarveHealthyWork(t *testing.T) {
	s := testStore(t)
	root := t.TempDir()
	sources := []Source{{Name: "pocs", Path: root, Kind: "poc"}}
	for i := 0; i < 4; i++ {
		os.WriteFile(filepath.Join(root, fmt.Sprintf("item-%d.md", i)), []byte("healthy fixture"), 0600)
	}
	docs, _, err := scanSources(sources)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(docs, func(i, j int) bool { return docs[i].ID < docs[j].ID })
	for _, d := range docs[:3] {
		os.WriteFile(filepath.Join(root, d.Path), []byte("BROKEN-FIXTURE"), 0600)
	}
	e := &selectiveEmbedder{mode: "partial"}
	svc := NewService(s, e, sources, zap.NewNop())
	defer svc.Close()
	ctx := context.Background()
	if err = svc.run(ctx, false); err == nil {
		t.Fatal("file failures errors hidden")
	}
	status, _ := svc.Status(ctx)
	if status.Ready != 1 || status.Failed != 3 || e.attempts != 4 {
		t.Fatalf("healthy work blocked: %+v attempts=%d", status, e.attempts)
	}
	attempts := e.attempts
	if err = svc.run(ctx, false); err != nil || e.attempts != attempts {
		t.Fatal("backoff ignored", err)
	}
	os.WriteFile(filepath.Join(root, "new.md"), []byte("new healthy fixture"), 0600)
	if err = svc.run(ctx, false); err != nil {
		t.Fatal(err)
	}
	status, _ = svc.Status(ctx)
	if status.Ready != 2 || status.Failed != 3 {
		t.Fatalf("new work blocked: %+v", status)
	}
	os.WriteFile(filepath.Join(root, docs[0].Path), []byte("repaired source"), 0600)
	if err = svc.run(ctx, false); err != nil {
		t.Fatal(err)
	}
	status, _ = svc.Status(ctx)
	if status.Ready != 3 || status.Failed != 2 {
		t.Fatalf("source edit did not reset retry: %+v", status)
	}
}

func TestGlobalOutageBudgetAndExplicitRetry(t *testing.T) {
	s := testStore(t)
	root := t.TempDir()
	for i := 0; i < 5; i++ {
		os.WriteFile(filepath.Join(root, fmt.Sprintf("item-%d.md", i)), []byte("healthy fixture"), 0600)
	}
	e := &selectiveEmbedder{mode: "outage"}
	svc := NewService(s, e, []Source{{Name: "pocs", Path: root, Kind: "poc"}}, zap.NewNop())
	defer svc.Close()
	ctx := context.Background()
	if err := svc.run(ctx, false); err == nil || e.attempts != 3 {
		t.Fatal("outage budget not enforced", err, e.attempts)
	}
	e.mode = "online"
	if err := svc.run(ctx, false); err != nil {
		t.Fatal(err)
	}
	status, _ := svc.Status(ctx)
	if status.Ready != 2 || status.Failed != 3 {
		t.Fatalf("fresh work did not precede deferred retries: %+v", status)
	}
	if err := svc.Trigger(ctx, false); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		status, _ = svc.Status(ctx)
		if !status.Running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("manual retry timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if status.Ready != 5 || status.Failed != 0 {
		t.Fatalf("explicit retry did not bypass backoff: %+v", status)
	}
}

func TestCompleteCVEIndexAndSourceReplacement(t *testing.T) {
	s := testStore(t)
	root := t.TempDir()
	var body strings.Builder
	for i := 0; i < 51; i++ {
		fmt.Fprintf(&body, "CVE-2099-%05d\n", 40000+i)
	}
	body.WriteString("cve-2099-40050\n")
	file := filepath.Join(root, "cross-reference.md")
	os.WriteFile(file, []byte(body.String()), 0600)
	svc := NewService(s, &fakeEmbedder{}, []Source{{Name: "references", Path: root, Kind: "reference"}}, zap.NewNop())
	defer svc.Close()
	ctx := context.Background()
	if err := svc.run(ctx, false); err != nil {
		t.Fatal(err)
	}
	approveAll(t, s)
	r, err := svc.Search(ctx, Search{CVE: "CVE-2099-40050", Page: 1})
	if err != nil || r.Total != 1 {
		t.Fatalf("last CVE missing: %+v %v", r, err)
	}
	d, err := s.Get(ctx, r.Items[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Metadata.DetectedCVEs) != 50 || d.DetectedCVECount != 51 {
		t.Fatalf("preview/count incorrect: %+v", d)
	}
	r, err = svc.Search(ctx, Search{Query: "CVE-2099-40050", Page: 1})
	if err != nil || len(r.Items) != 1 || r.Items[0].Score < 1 {
		t.Fatal("exact CVE lost priority", err)
	}
	d.Metadata.CVEs = []string{"CVE-2099-99999"}
	if err = svc.Edit(ctx, d.ID, "reviewer", Edit{Title: d.Title, Kind: d.Kind, Review: d.Review, Metadata: d.Metadata, Revision: d.Revision}); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(file, []byte("new source CVE-2099-40051"), 0600)
	if err = svc.run(ctx, false); err != nil {
		t.Fatal(err)
	}
	approveAll(t, s)
	for id, want := range map[string]int{"CVE-2099-40050": 0, "CVE-2099-40051": 1, "CVE-2099-99999": 1} {
		r, err = svc.Search(ctx, Search{CVE: id, Page: 1})
		if err != nil || r.Total != want {
			t.Fatalf("CVE %s got=%d want=%d err=%v", id, r.Total, want, err)
		}
	}
}

func TestReviewStateIsAPublicationGate(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	d := document("pending.md", "reference", "publication gate fixture")
	if err := s.saveScan(ctx, []Document{d}); err != nil {
		t.Fatal(err)
	}
	if items, total, err := s.keyword(ctx, Search{Page: 1}); err != nil || total != 0 || len(items) != 0 {
		t.Fatalf("pending document leaked into default search: total=%d items=%d err=%v", total, len(items), err)
	}
	if items, total, err := s.keyword(ctx, Search{Review: "all", Page: 1}); err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("review queue could not inspect pending document: total=%d items=%d err=%v", total, len(items), err)
	}
	d, _ = s.Get(ctx, d.ID)
	if err := s.Edit(ctx, d.ID, "reviewer", Edit{Title: d.Title, Kind: d.Kind, Review: "reviewed", Metadata: d.Metadata, Revision: d.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, total, err := s.keyword(ctx, Search{Page: 1}); err != nil || total != 1 {
		t.Fatalf("approved document was not published: total=%d err=%v", total, err)
	}
	d, _ = s.Get(ctx, d.ID)
	if err := s.Edit(ctx, d.ID, "reviewer", Edit{Title: d.Title, Kind: d.Kind, Review: "rejected", Metadata: d.Metadata, Revision: d.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, total, err := s.keyword(ctx, Search{Page: 1}); err != nil || total != 0 {
		t.Fatalf("disabled document remained published: total=%d err=%v", total, err)
	}
	if _, total, err := s.keyword(ctx, Search{Review: "rejected", Page: 1}); err != nil || total != 1 {
		t.Fatalf("disabled document disappeared from management view: total=%d err=%v", total, err)
	}
	if err := (Search{Review: "all", Page: 1}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestApprovedSkillManifestTracksReviewState(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	base := t.TempDir()
	skillsDir := filepath.Join(base, "skills")
	if err := os.MkdirAll(filepath.Join(skillsDir, "demo"), 0700); err != nil {
		t.Fatal(err)
	}
	content := "---\nname: demo\ndescription: review gate fixture\n---\n# Demo\n"
	if err := os.WriteFile(filepath.Join(skillsDir, "demo", "SKILL.md"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	sources := []Source{{Name: "skills", Path: skillsDir, Kind: "reference"}}
	docs, _, err := scanSources(sources)
	if err != nil || len(docs) != 1 {
		t.Fatalf("scan: %d %v", len(docs), err)
	}
	if err = s.saveScan(ctx, docs); err != nil {
		t.Fatal(err)
	}
	service := NewService(s, &fakeEmbedder{}, sources, zap.NewNop())
	defer service.Close()
	if err = service.syncApprovedSkills(ctx); err != nil {
		t.Fatal(err)
	}
	names, found, err := LoadApprovedSkillNames(skillsDir)
	if err != nil || !found || len(names) != 0 {
		t.Fatalf("pending manifest: found=%v names=%v err=%v", found, names, err)
	}
	d, _ := s.Get(ctx, docs[0].ID)
	if err = s.Edit(ctx, d.ID, "reviewer", Edit{Title: d.Title, Kind: d.Kind, Review: "reviewed", Metadata: d.Metadata, Revision: d.Revision}); err != nil {
		t.Fatal(err)
	}
	if err = service.syncApprovedSkills(ctx); err != nil {
		t.Fatal(err)
	}
	names, found, err = LoadApprovedSkillNames(skillsDir)
	if err != nil || !found {
		t.Fatal(err)
	}
	if _, ok := names["demo"]; !ok || len(names) != 1 {
		t.Fatalf("approved skill not published: %v", names)
	}
}
func TestSearchIndexMigrationPreservesExistingData(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	var body strings.Builder
	for i := 0; i < 51; i++ {
		fmt.Fprintf(&body, "CVE-2099-%05d\n", 50000+i)
	}
	d := document("legacy.md", "reference", body.String())
	d.Metadata.DetectedCVEs = detectCVEs(d.Content)[:50]
	d.Metadata.CVEs = []string{"CVE-2099-99999"}
	d.Metadata.Notes = "keep reviewer annotation"
	if err := s.saveScan(ctx, []Document{d}); err != nil {
		t.Fatal(err)
	}
	d, _ = s.Get(ctx, d.ID)
	if err := s.Edit(ctx, d.ID, "reviewer", Edit{Title: d.Title, Kind: d.Kind, Review: "reviewed", Metadata: d.Metadata, Revision: d.Revision}); err != nil {
		t.Fatal(err)
	}
	d, _ = s.Get(ctx, d.ID)
	if err := s.saveVectors(ctx, d, []string{d.Content}, [][]float32{vectorAt(0)}, "model-v1"); err != nil {
		t.Fatal(err)
	}
	fingerprint := func(query string) string {
		t.Helper()
		var value string
		if err := s.db.QueryRow(query).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	const vectorFingerprint = `SELECT md5(string_agg(row_to_json(c)::text||c.xmin::text,'' ORDER BY document_id,chunk_index)) FROM skill_library_chunks c`
	const sourceFingerprint = `SELECT md5(jsonb_build_array(source_hash,content,metadata,review,revision,index_hash,model_key,updated_at,state)::text) FROM skill_library_documents`
	vectorsBefore, sourceBefore := fingerprint(vectorFingerprint), fingerprint(sourceFingerprint)
	_, err := s.db.Exec(`DROP TABLE skill_library_text_chunks,skill_library_document_cves,skill_library_schema;
ALTER TABLE skill_library_documents DROP COLUMN detected_cve_count,DROP COLUMN failure_count,DROP COLUMN retry_after,DROP COLUMN retry_model_key;
CREATE INDEX skill_library_fts ON skill_library_documents USING gin(to_tsvector('simple',title||' '||content))`)
	if err != nil {
		t.Fatal(err)
	}
	if s, err = NewStore(ctx, s.db); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"CVE-2099-50050", "CVE-2099-99999"} {
		_, total, err := s.keyword(ctx, Search{CVE: id, Page: 1})
		if err != nil || total != 1 {
			t.Fatalf("migration lost %s: %d %v", id, total, err)
		}
	}
	if fingerprint(`SELECT COALESCE(to_regclass('skill_library_fts')::text,'absent')`) != "absent" {
		t.Fatal("unsafe index retained")
	}
	d, err = s.Get(ctx, d.ID)
	if err != nil || d.DetectedCVECount != 51 || len(d.Metadata.DetectedCVEs) != 50 {
		t.Fatalf("migrated CVE count: %d %v", d.DetectedCVECount, err)
	}
	if vectorsBefore != fingerprint(vectorFingerprint) || sourceBefore != fingerprint(sourceFingerprint) {
		t.Fatal("migration modified vectors or source annotations")
	}
	const keywordFingerprint = `SELECT md5(string_agg(row_to_json(k)::text||k.xmin::text,'' ORDER BY document_id,chunk_index)) FROM skill_library_text_chunks k`
	keywords := fingerprint(keywordFingerprint)
	if _, err = NewStore(ctx, s.db); err != nil {
		t.Fatal(err)
	}
	if keywords != fingerprint(keywordFingerprint) {
		t.Fatal("migration unnecessarily rebuilt keyword chunks")
	}
}

func TestRetryBackoffModelChangeAndStaleGeneration(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	d := document("retry.md", "reference", "fixture")
	if err := s.saveScan(ctx, []Document{d}); err != nil {
		t.Fatal(err)
	}
	d, _ = s.Get(ctx, d.ID)
	for i, minutes := range []float64{1, 5, 15, 60, 60} {
		if err := s.markFailed(ctx, d, "model-v1", errors.New("fixture rejected")); err != nil {
			t.Fatal(err)
		}
		var failures int
		var seconds float64
		err := s.db.QueryRow(`SELECT failure_count,EXTRACT(EPOCH FROM retry_after-CURRENT_TIMESTAMP) FROM skill_library_documents WHERE id=$1`, d.ID).Scan(&failures, &seconds)
		if err != nil || failures != i+1 || math.Abs(seconds-minutes*60) > 5 {
			t.Fatalf("backoff step=%d count=%d seconds=%f err=%v", i, failures, seconds, err)
		}
	}
	pending, err := s.Pending(ctx, "model-v1")
	if err != nil || len(pending) != 0 {
		t.Fatal("deferred retry scheduled", err)
	}
	pending, err = s.Pending(ctx, "model-v2")
	if err != nil || len(pending) != 1 {
		t.Fatal("new model blocked by old backoff", err)
	}
	if err = s.markFailed(ctx, d, "model-v2", errors.New("fixture rejected")); err != nil {
		t.Fatal(err)
	}
	var failures int
	if err = s.db.QueryRow(`SELECT failure_count FROM skill_library_documents WHERE id=$1`, d.ID).Scan(&failures); err != nil || failures != 1 {
		t.Fatal("new model retained old failure count", failures, err)
	}
	stale := d
	d.Content = "new source"
	d.Hash = digest(d.Content)
	if err = s.saveScan(ctx, []Document{d}); err != nil {
		t.Fatal(err)
	}
	if err = s.markFailed(ctx, stale, "model-v1", errors.New("stale failure")); err != nil {
		t.Fatal(err)
	}
	d, err = s.Get(ctx, d.ID)
	if err != nil || d.State != "pending" || d.Error != "" {
		t.Fatal("stale failure overwrote changed source", err)
	}
}

func TestEmbeddingFailureClassification(t *testing.T) {
	for _, status := range []int{400, 404, 429, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			defer server.Close()
			e, err := NewLocalEmbedder(server.URL, "fixture", "")
			if err != nil {
				t.Fatal(err)
			}
			_, err = e.Embed(context.Background(), []string{"fixture"})
			if err == nil || errors.Is(err, ErrEmbeddingUnavailable) != (status != 400) {
				t.Fatalf("status=%d err=%v", status, err)
			}
		})
	}
}

func TestRankFusionExactIdentifiersAndPagination(t *testing.T) {
	a := document("exact", "reference", "")
	a.Metadata.CVEs = []string{"CVE-2021-44228"}
	a.Matches = []string{"keyword"}
	b := document("similar", "skill", "")
	b.Matches = []string{"semantic"}
	result := fuse([]Document{a}, []Document{b}, "CVE-2021-44228")
	if len(result) != 2 || result[0].ID != a.ID {
		t.Fatal("exact ID lost priority")
	}
	items := make([]Document, 60)
	if len(pageItems(items, 1)) != 25 || len(pageItems(items, 3)) != 10 || len(pageItems(items, 4)) != 0 {
		t.Fatal("pagination")
	}
	if (Search{Query: "ok", Page: 0}).Validate() == nil {
		t.Fatal("invalid page")
	}
}

func TestEmbeddingRevisionMismatchStopsRequests(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/embed" {
			calls++
		}
		json.NewEncoder(w).Encode(map[string]any{"models": []map[string]string{{"name": "bge-m3:latest", "digest": "new"}}})
	}))
	defer server.Close()
	e, err := NewLocalEmbedder(server.URL, "bge-m3", "old")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Embed(context.Background(), []string{"test"}); err == nil || calls != 0 {
		t.Fatal("different model revision used")
	}
}

func TestBackgroundIndexBusyAndShutdown(t *testing.T) {
	s := testStore(t)
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "a.txt"), []byte("data"), 0600)
	e := &blockingEmbedder{started: make(chan struct{})}
	service := NewService(s, e, []Source{{Name: "pocs", Path: root, Kind: "poc"}}, zap.NewNop())
	if err := service.Trigger(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-e.started:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not start")
	}
	if err := service.Trigger(context.Background(), false); !errors.Is(err, ErrBusy) {
		t.Fatal("concurrent job accepted")
	}
	done := make(chan struct{})
	go func() { service.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not cancel embedding")
	}
	status, err := service.Status(context.Background())
	if err != nil || status.Running {
		t.Fatal("running state not cleared", err)
	}
}

type blockingEmbedder struct{ started chan struct{} }

func (e *blockingEmbedder) Key() string   { return "blocking" }
func (e *blockingEmbedder) Model() string { return "blocking" }
func (e *blockingEmbedder) Embed(ctx context.Context, _ []string) ([][]float32, error) {
	close(e.started)
	<-ctx.Done()
	return nil, ctx.Err()
}
