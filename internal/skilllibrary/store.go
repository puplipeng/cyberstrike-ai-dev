package skilllibrary

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type Store struct{ db *sql.DB }

func NewStore(ctx context.Context, db *sql.DB) (*Store, error) {
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

const columns = `id,root,path,kind,title,skill,source_hash,content,metadata,review,state,error,revision,missing,updated_at,index_hash,model_key,detected_cve_count`

type rowScanner interface{ Scan(...any) error }

func scanDocument(row rowScanner) (Document, error) {
	var d Document
	var raw []byte
	err := row.Scan(&d.ID, &d.Root, &d.Path, &d.Kind, &d.Title, &d.Skill, &d.Hash, &d.Content, &raw, &d.Review, &d.State, &d.Error, &d.Revision, &d.Missing, &d.Updated, &d.IndexHash, &d.ModelKey, &d.DetectedCVECount)
	if err == nil {
		err = json.Unmarshal(raw, &d.Metadata)
	}
	return d, err
}
func (s *Store) Get(ctx context.Context, id string) (Document, error) {
	if !validID(id) {
		return Document{}, ErrInvalid
	}
	return scanDocument(s.db.QueryRowContext(ctx, `SELECT `+columns+` FROM skill_library_documents WHERE id=$1`, id))
}

// A complete filesystem scan commits atomically. Scan failures never mark existing files missing.
func (s *Store) saveScan(ctx context.Context, docs []Document) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ids := []string{}
	for _, d := range docs {
		old, e := scanDocument(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM skill_library_documents WHERE id=$1 FOR UPDATE`, d.ID))
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if e == nil {
			// Metadata is a user annotation, never overwritten by an automatic scan.
			detected := d.Metadata.DetectedCVEs
			d.Metadata = old.Metadata
			d.Metadata.DetectedCVEs = detected
			d.Title = old.Title
			d.Kind = old.Kind
		}
		d.IndexHash = indexHash(d)
		raw, _ := json.Marshal(d.Metadata)
		_, err = tx.ExecContext(ctx, `INSERT INTO skill_library_documents(id,root,path,kind,title,skill,source_hash,content,metadata,index_hash)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(id) DO UPDATE SET
 source_hash=EXCLUDED.source_hash,content=EXCLUDED.content,metadata=EXCLUDED.metadata,index_hash=EXCLUDED.index_hash,missing=false,
 state=CASE WHEN skill_library_documents.index_hash<>EXCLUDED.index_hash OR skill_library_documents.missing THEN 'pending' ELSE skill_library_documents.state END,
 error=CASE WHEN skill_library_documents.index_hash<>EXCLUDED.index_hash OR skill_library_documents.missing THEN '' ELSE skill_library_documents.error END,
 failure_count=CASE WHEN skill_library_documents.index_hash<>EXCLUDED.index_hash OR skill_library_documents.missing THEN 0 ELSE skill_library_documents.failure_count END,
 retry_after=CASE WHEN skill_library_documents.index_hash<>EXCLUDED.index_hash OR skill_library_documents.missing THEN NULL ELSE skill_library_documents.retry_after END,
 retry_model_key=CASE WHEN skill_library_documents.index_hash<>EXCLUDED.index_hash OR skill_library_documents.missing THEN '' ELSE skill_library_documents.retry_model_key END,
 review=CASE WHEN skill_library_documents.source_hash<>EXCLUDED.source_hash THEN 'unreviewed' ELSE skill_library_documents.review END,
 revision=skill_library_documents.revision+CASE WHEN skill_library_documents.source_hash<>EXCLUDED.source_hash OR skill_library_documents.missing THEN 1 ELSE 0 END,
 updated_at=CASE WHEN skill_library_documents.source_hash<>EXCLUDED.source_hash OR skill_library_documents.missing THEN CURRENT_TIMESTAMP ELSE skill_library_documents.updated_at END`, d.ID, d.Root, d.Path, d.Kind, d.Title, d.Skill, d.Hash, d.Content, string(raw), d.IndexHash)
		if err != nil {
			return err
		}
		if e != nil || old.IndexHash != d.IndexHash || old.Missing {
			if err = replaceSearchIndexes(ctx, tx, d); err != nil {
				return err
			}
		}
		ids = append(ids, d.ID)
	}
	_, err = tx.ExecContext(ctx, `UPDATE skill_library_documents SET missing=true,state='missing',revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE NOT missing AND NOT(id=ANY($1::text[]))`, ids)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO skill_library_links(skill_id,resource_id,source,actor)
 SELECT s.id,r.id,'package','scanner' FROM skill_library_documents s JOIN skill_library_documents r ON r.root='skills' AND s.skill=r.skill AND s.id<>r.id
 WHERE s.kind='skill' AND s.root='skills' AND NOT s.missing AND NOT r.missing ON CONFLICT DO NOTHING`)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Pending(ctx context.Context, key string) ([]Document, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+columns+` FROM skill_library_documents
 WHERE NOT missing AND (state<>'ready' OR model_key<>$1)
 AND (state<>'error' OR retry_model_key<>$1 OR retry_after IS NULL OR retry_after<=CURRENT_TIMESTAMP)
 ORDER BY CASE WHEN state='error' AND retry_model_key=$1 THEN 1 ELSE 0 END,
 retry_after NULLS FIRST,CASE kind WHEN 'skill' THEN 0 ELSE 1 END,id`, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	docs := []Document{}
	for rows.Next() {
		d, e := scanDocument(rows)
		if e != nil {
			return nil, e
		}
		docs = append(docs, d)
	}
	return docs, rows.Err()
}
func (s *Store) saveVectors(ctx context.Context, d Document, texts []string, vectors [][]float32, key string) error {
	if len(texts) != len(vectors) || len(texts) == 0 {
		return ErrInvalid
	}
	for _, v := range vectors {
		if !validVector(v) {
			return ErrInvalid
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var hash string
	var missing bool
	if err = tx.QueryRowContext(ctx, `SELECT index_hash,missing FROM skill_library_documents WHERE id=$1 FOR UPDATE`, d.ID).Scan(&hash, &missing); err != nil {
		return err
	}
	if missing || hash != d.IndexHash {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM skill_library_chunks WHERE document_id=$1`, d.ID); err != nil {
		return err
	}
	for i, v := range vectors {
		raw, _ := json.Marshal(v)
		_, err = tx.ExecContext(ctx, `INSERT INTO skill_library_chunks(document_id,chunk_index,content,index_hash,model_key,embedding)VALUES($1,$2,$3,$4,$5,$6::vector)`, d.ID, i, texts[i], d.IndexHash, key, string(raw))
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE skill_library_documents SET state='ready',error='',model_key=$2,failure_count=0,retry_after=NULL,retry_model_key='' WHERE id=$1`, d.ID, key)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) markFailed(ctx context.Context, d Document, key string, cause error) error {
	_, err := s.db.ExecContext(ctx, `UPDATE skill_library_documents SET state='error',error=$2,
 retry_after=CURRENT_TIMESTAMP+CASE
 WHEN retry_model_key<>$4 OR failure_count=0 THEN INTERVAL '1 minute'
 WHEN failure_count=1 THEN INTERVAL '5 minutes'
 WHEN failure_count=2 THEN INTERVAL '15 minutes'
 ELSE INTERVAL '1 hour' END,
 failure_count=CASE WHEN retry_model_key=$4 THEN LEAST(failure_count+1,32) ELSE 1 END,
 retry_model_key=$4 WHERE id=$1 AND index_hash=$3 AND NOT missing`, d.ID, short(cause.Error(), 250), d.IndexHash, key)
	return err
}
func (s *Store) Status(ctx context.Context, key, model string) (Status, error) {
	out := Status{Model: model, Dimension: Dimension}
	err := s.db.QueryRowContext(ctx, `SELECT running,phase,last_run,last_error,skipped FROM skill_library_job WHERE id=1`).Scan(&out.Running, &out.Phase, &out.LastRun, &out.LastError, &out.Skipped)
	if err != nil {
		return out, err
	}
	err = s.db.QueryRowContext(ctx, `SELECT
 COUNT(*) FILTER(WHERE NOT missing),
 COUNT(*) FILTER(WHERE NOT missing AND state='ready' AND model_key=$1),
 COUNT(*) FILTER(WHERE NOT missing AND state<>'error' AND (state<>'ready' OR model_key<>$1)),
 COUNT(*) FILTER(WHERE NOT missing AND state='error'),
 COUNT(*) FILTER(WHERE missing),
 COUNT(*) FILTER(WHERE NOT missing AND review='reviewed'),
 COUNT(*) FILTER(WHERE NOT missing AND review='unreviewed'),
 COUNT(*) FILTER(WHERE NOT missing AND review='rejected'),
 COUNT(*) FILTER(WHERE NOT missing AND review='reviewed' AND state='ready' AND model_key=$1)
 FROM skill_library_documents`, key).Scan(&out.Total, &out.Ready, &out.Pending, &out.Failed, &out.Missing, &out.Approved, &out.AwaitingReview, &out.Disabled, &out.Available)
	if err != nil {
		return out, err
	}
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM skill_library_chunks c JOIN skill_library_documents d ON d.id=c.document_id WHERE NOT d.missing AND d.state='ready' AND c.index_hash=d.index_hash AND c.model_key=$1`, key).Scan(&out.Chunks)
	return out, err
}

type Edit struct {
	Title    string   `json:"title"`
	Kind     string   `json:"kind"`
	Review   string   `json:"review"`
	Metadata Metadata `json:"metadata"`
	Revision int64    `json:"revision"`
}

func (s *Store) Edit(ctx context.Context, id, actor string, edit Edit) error {
	if strings.TrimSpace(edit.Title) == "" || len(edit.Title) > 300 || strings.ContainsRune(edit.Title, 0) || edit.Metadata.Validate() != nil {
		return ErrInvalid
	}
	if edit.Kind != "skill" && edit.Kind != "reference" && edit.Kind != "poc" {
		return ErrInvalid
	}
	if edit.Review != "unreviewed" && edit.Review != "reviewed" && edit.Review != "rejected" {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	d, err := scanDocument(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM skill_library_documents WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return err
	}
	if d.Missing || d.Revision != edit.Revision {
		return ErrConflict
	}
	if (d.Kind == "skill") != (edit.Kind == "skill") {
		return ErrInvalid
	}
	edit.Metadata.DetectedCVEs = d.Metadata.DetectedCVEs
	d.Title = edit.Title
	d.Metadata = edit.Metadata
	hash := indexHash(d)
	raw, _ := json.Marshal(d.Metadata)
	_, err = tx.ExecContext(ctx, `UPDATE skill_library_documents SET title=$2,kind=$3,metadata=$4,review=$5,index_hash=$6,
 state=CASE WHEN index_hash<>$6 THEN 'pending' ELSE state END,
 error=CASE WHEN index_hash<>$6 THEN '' ELSE error END,
 failure_count=CASE WHEN index_hash<>$6 THEN 0 ELSE failure_count END,
 retry_after=CASE WHEN index_hash<>$6 THEN NULL ELSE retry_after END,
 retry_model_key=CASE WHEN index_hash<>$6 THEN '' ELSE retry_model_key END,
 revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE id=$1`, id, d.Title, edit.Kind, string(raw), edit.Review, hash)
	if err != nil {
		return err
	}
	if d.IndexHash != hash {
		if err = replaceSearchIndexes(ctx, tx, d); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO skill_library_audit(actor,action,document_id)VALUES($1,'metadata',$2)`, actor, id)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Links(ctx context.Context, id string) ([]Link, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT l.skill_id,l.resource_id,s.title,r.title,l.source,l.note FROM skill_library_links l JOIN skill_library_documents s ON s.id=l.skill_id JOIN skill_library_documents r ON r.id=l.resource_id WHERE (l.skill_id=$1 OR l.resource_id=$1) ORDER BY l.created_at DESC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Link{}
	for rows.Next() {
		var l Link
		if err = rows.Scan(&l.SkillID, &l.ResourceID, &l.SkillTitle, &l.ResourceTitle, &l.Source, &l.Note); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
func (s *Store) Link(ctx context.Context, l Link, actor string, remove bool) error {
	if !validID(l.SkillID) || !validID(l.ResourceID) || l.SkillID == l.ResourceID || len(l.Note) > 2000 || strings.ContainsRune(l.Note, 0) {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if remove {
		res, e := tx.ExecContext(ctx, `DELETE FROM skill_library_links WHERE skill_id=$1 AND resource_id=$2 AND source='manual'`, l.SkillID, l.ResourceID)
		if e != nil {
			return e
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return sql.ErrNoRows
		}
	} else {
		res, e := tx.ExecContext(ctx, `INSERT INTO skill_library_links(skill_id,resource_id,source,note,actor)
 SELECT s.id,r.id,'manual',$3,$4 FROM skill_library_documents s,skill_library_documents r
 WHERE s.id=$1 AND r.id=$2 AND s.kind='skill' AND r.kind<>'skill' AND NOT s.missing AND NOT r.missing
 ON CONFLICT(skill_id,resource_id)DO UPDATE SET note=EXCLUDED.note WHERE skill_library_links.source='manual'`, l.SkillID, l.ResourceID, l.Note, actor)
		if e != nil {
			return e
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return ErrInvalid
		}
	}
	action := "link"
	if remove {
		action = "unlink"
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO skill_library_audit(actor,action,document_id)VALUES($1,$2,$3)`, actor, action, l.ResourceID)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func conditions(f Search, start int) (string, []any) {
	where := `NOT d.missing`
	args := []any{}
	add := func(s string, v any) { args = append(args, v); where += fmt.Sprintf(s, start+len(args)-1) }
	if f.Kind != "" {
		add(` AND d.kind=$%d`, f.Kind)
	}
	if f.Review == "" {
		where += ` AND d.review='reviewed'`
	} else if f.Review != "all" {
		add(` AND d.review=$%d`, f.Review)
	}
	if f.CVE != "" {
		add(` AND EXISTS(SELECT 1 FROM skill_library_document_cves cv WHERE cv.document_id=d.id AND cv.cve=$%d)`, strings.ToUpper(f.CVE))
	}
	if f.Product != "" {
		add(` AND strpos(lower((d.metadata->'products')::text),lower($%d))>0`, f.Product)
	}
	return where, args
}
