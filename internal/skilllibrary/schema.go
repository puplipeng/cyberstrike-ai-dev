package skilllibrary

import (
	"context"
	"database/sql"
	"strings"
)

// Migrate keyword/CVE indexes without changing source snapshots or embeddings.
func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(739522002)`); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS skill_library_documents(
 id TEXT PRIMARY KEY,root TEXT NOT NULL,path TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN('skill','reference','poc')),
 title TEXT NOT NULL,skill TEXT NOT NULL,source_hash TEXT NOT NULL,content TEXT NOT NULL,metadata JSONB NOT NULL,
 review TEXT NOT NULL DEFAULT 'unreviewed' CHECK(review IN('unreviewed','reviewed','rejected')),
 state TEXT NOT NULL DEFAULT 'pending',error TEXT NOT NULL DEFAULT '',revision BIGINT NOT NULL DEFAULT 1,
 missing BOOLEAN NOT NULL DEFAULT false,index_hash TEXT NOT NULL,model_key TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,UNIQUE(root,path));
ALTER TABLE skill_library_documents
 ADD COLUMN IF NOT EXISTS detected_cve_count INTEGER NOT NULL DEFAULT 0,
 ADD COLUMN IF NOT EXISTS failure_count INTEGER NOT NULL DEFAULT 0,
 ADD COLUMN IF NOT EXISTS retry_after TIMESTAMPTZ,
 ADD COLUMN IF NOT EXISTS retry_model_key TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS skill_library_chunks(
 document_id TEXT NOT NULL REFERENCES skill_library_documents(id) ON DELETE CASCADE,
 chunk_index INTEGER NOT NULL,content TEXT NOT NULL,index_hash TEXT NOT NULL,model_key TEXT NOT NULL,
 embedding vector(1024) NOT NULL,PRIMARY KEY(document_id,chunk_index));
CREATE INDEX IF NOT EXISTS skill_library_chunks_hnsw ON skill_library_chunks USING hnsw(embedding vector_cosine_ops);
CREATE TABLE IF NOT EXISTS skill_library_links(
 skill_id TEXT NOT NULL REFERENCES skill_library_documents(id) ON DELETE CASCADE,
 resource_id TEXT NOT NULL REFERENCES skill_library_documents(id) ON DELETE CASCADE,
 source TEXT NOT NULL CHECK(source IN('package','manual')),note TEXT NOT NULL DEFAULT '',actor TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(skill_id,resource_id));
CREATE TABLE IF NOT EXISTS skill_library_job(
 id INTEGER PRIMARY KEY CHECK(id=1),running BOOLEAN NOT NULL DEFAULT false,phase TEXT NOT NULL DEFAULT 'idle',
 last_run TIMESTAMPTZ,last_error TEXT NOT NULL DEFAULT '',skipped INTEGER NOT NULL DEFAULT 0);
INSERT INTO skill_library_job(id)VALUES(1)ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS skill_library_audit(
 id BIGSERIAL PRIMARY KEY,actor TEXT NOT NULL,action TEXT NOT NULL,document_id TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS skill_library_text_chunks(
 document_id TEXT NOT NULL REFERENCES skill_library_documents(id) ON DELETE CASCADE,
 chunk_index INTEGER NOT NULL,content TEXT NOT NULL,
 search_vector TSVECTOR GENERATED ALWAYS AS (to_tsvector('simple',content)) STORED,
 PRIMARY KEY(document_id,chunk_index));
CREATE INDEX IF NOT EXISTS skill_library_text_fts ON skill_library_text_chunks USING gin(search_vector);
CREATE TABLE IF NOT EXISTS skill_library_document_cves(
 document_id TEXT NOT NULL REFERENCES skill_library_documents(id) ON DELETE CASCADE,
 cve TEXT NOT NULL,PRIMARY KEY(document_id,cve));
CREATE INDEX IF NOT EXISTS skill_library_cve_lookup ON skill_library_document_cves(cve,document_id);
CREATE TABLE IF NOT EXISTS skill_library_schema(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL);
INSERT INTO skill_library_schema(id,version)VALUES(1,0)ON CONFLICT DO NOTHING;
`)
	if err != nil {
		return err
	}
	var version int
	if err = tx.QueryRowContext(ctx, `SELECT version FROM skill_library_schema WHERE id=1`).Scan(&version); err != nil {
		return err
	}
	if version < 2 {
		// The legacy expression index can reject an otherwise valid 1 MiB file.
		if _, err = tx.ExecContext(ctx, `DROP INDEX IF EXISTS skill_library_fts`); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT `+columns+` FROM skill_library_documents ORDER BY id`)
		if err != nil {
			return err
		}
		docs := []Document{}
		for rows.Next() {
			d, err := scanDocument(rows)
			if err != nil {
				rows.Close()
				return err
			}
			docs = append(docs, d)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, d := range docs {
			if err = replaceSearchIndexes(ctx, tx, d); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, `UPDATE skill_library_schema SET version=2 WHERE id=1`); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// These indexes are committed with the source snapshot, independently of embeddings.
func replaceSearchIndexes(ctx context.Context, tx *sql.Tx, d Document) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM skill_library_text_chunks WHERE document_id=$1`, d.ID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO skill_library_text_chunks(document_id,chunk_index,content)
SELECT $1,(ordinality-1)::integer,fragment FROM unnest($2::text[]) WITH ORDINALITY AS t(fragment,ordinality)
`, d.ID, chunks(d.Title+"\n"+d.Content))
	if err != nil {
		return err
	}
	detected := detectCVEs(d.Content)
	ids := append([]string{}, detected...)
	seen := map[string]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	for _, id := range d.Metadata.CVEs {
		id = strings.ToUpper(strings.TrimSpace(id))
		if !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM skill_library_document_cves WHERE document_id=$1`, d.ID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO skill_library_document_cves(document_id,cve) SELECT $1,unnest($2::text[])`, d.ID, ids); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE skill_library_documents SET detected_cve_count=$2 WHERE id=$1`, d.ID, len(detected))
	return err
}
