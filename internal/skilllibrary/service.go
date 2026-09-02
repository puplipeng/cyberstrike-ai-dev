package skilllibrary

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const indexLockID int64 = 739522001

type Service struct {
	store           *Store
	embed           Embedder
	sources         []Source
	logger          *zap.Logger
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.Mutex
	running, closed bool
	wg              sync.WaitGroup
	start           sync.Once
}

func NewService(store *Store, embed Embedder, sources []Source, logger *zap.Logger) *Service {
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{store: store, embed: embed, sources: sources, logger: logger, ctx: ctx, cancel: cancel}
}
func (s *Service) Store() *Store { return s.store }
func (s *Service) Status(ctx context.Context) (Status, error) {
	return s.store.Status(ctx, s.embed.Key(), s.embed.Model())
}
func (s *Service) Start(ctx context.Context) {
	s.start.Do(func() {
		if err := s.syncApprovedSkills(ctx); err != nil {
			s.logger.Error("sync approved Agent skills failed", zap.Error(err))
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			_ = s.trigger(s.ctx, false, false)
			for {
				select {
				case <-ctx.Done():
					s.cancel()
					return
				case <-s.ctx.Done():
					return
				case <-ticker.C:
					_ = s.trigger(s.ctx, false, false)
				}
			}
		}()
	})
}
func (s *Service) Close() { s.mu.Lock(); s.closed = true; s.cancel(); s.mu.Unlock(); s.wg.Wait() }
func (s *Service) Trigger(ctx context.Context, full bool) error {
	return s.trigger(ctx, full, true)
}
func (s *Service) trigger(ctx context.Context, full, manual bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return context.Canceled
	}
	if s.running {
		return ErrBusy
	}
	conn, err := s.store.db.Conn(ctx)
	if err != nil {
		return err
	}
	var locked bool
	if err = conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, indexLockID).Scan(&locked); err != nil || !locked {
		conn.Close()
		if err != nil {
			return err
		}
		return ErrBusy
	}
	if _, err = conn.ExecContext(ctx, `UPDATE skill_library_job SET running=true,phase='scanning',last_error='' WHERE id=1`); err != nil {
		s.unlock(conn)
		return err
	}
	s.running = true
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() { s.unlock(conn); s.mu.Lock(); s.running = false; s.mu.Unlock() }()
		jobCtx, cancel := context.WithTimeout(s.ctx, 2*time.Hour)
		defer cancel()
		var err error
		if manual {
			// Explicit user retries bypass the automatic backoff without discarding failure history.
			_, err = s.store.db.ExecContext(jobCtx, `UPDATE skill_library_documents SET retry_after=NULL WHERE state='error' AND NOT missing`)
		}
		if err == nil {
			err = s.run(jobCtx, full)
		}
		lastError := ""
		phase := "idle"
		if err != nil {
			lastError = short(err.Error(), 300)
			phase = "error"
			s.logger.Warn("skill library index failed", zap.Error(err))
		}
		cleanup, cancelCleanup := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelCleanup()
		_, _ = conn.ExecContext(cleanup, `UPDATE skill_library_job SET running=false,phase=$1,last_error=$2,last_run=CURRENT_TIMESTAMP WHERE id=1`, phase, lastError)
	}()
	return nil
}
func (s *Service) unlock(conn *sql.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, e := conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, indexLockID); e != nil {
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	}
	conn.Close()
}
func (s *Service) run(ctx context.Context, full bool) error {
	docs, skipped, err := scanSources(s.sources)
	if err != nil {
		return err
	}
	if err = s.store.saveScan(ctx, docs); err != nil {
		return err
	}
	if err = s.syncApprovedSkills(ctx); err != nil {
		return err
	}
	_, err = s.store.db.ExecContext(ctx, `UPDATE skill_library_job SET phase='indexing',skipped=$1 WHERE id=1`, skipped)
	if err != nil {
		return err
	}
	if full {
		if _, err = s.store.db.ExecContext(ctx, `UPDATE skill_library_documents SET state='pending',error='',failure_count=0,retry_after=NULL,retry_model_key='' WHERE NOT missing`); err != nil {
			return err
		}
	}
	pending, err := s.store.Pending(ctx, s.embed.Key())
	if err != nil {
		return err
	}
	failed := 0
	unavailable := 0
	for _, d := range pending {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		texts := chunks(d.Content)
		if len(texts) == 0 {
			texts = []string{d.Title}
		}
		vectors := [][]float32{}
		var indexErr error
		for start := 0; start < len(texts); start += 4 {
			end := start + 4
			if end > len(texts) {
				end = len(texts)
			}
			input := []string{}
			for _, text := range texts[start:end] {
				input = append(input, short(d.Title+"\n"+strings.Join(d.Metadata.Products, ", ")+"\n"+strings.Join(d.Metadata.CVEs, ", ")+"\n"+d.Metadata.Versions+"\n"+d.Metadata.Prerequisites, 600)+"\n"+text)
			}
			var batch [][]float32
			batch, indexErr = s.embed.Embed(ctx, input)
			if indexErr != nil {
				break
			}
			vectors = append(vectors, batch...)
		}
		if indexErr == nil {
			indexErr = s.store.saveVectors(ctx, d, texts, vectors, s.embed.Key())
		}
		if errors.Is(indexErr, ErrConflict) {
			continue
		}
		if indexErr != nil {
			failed++
			if err := s.store.markFailed(ctx, d, s.embed.Key(), indexErr); err != nil {
				return err
			}
			if errors.Is(indexErr, ErrEmbeddingUnavailable) {
				unavailable++
			} else {
				unavailable = 0
			}
			if unavailable >= 3 {
				return fmt.Errorf("embedding failed for %d documents; remaining files stay queued", failed)
			}
		} else {
			unavailable = 0
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d documents could not be indexed; see document state", failed)
	}
	return nil
}
func (s *Service) SourceCurrent(d Document) bool {
	for _, source := range s.sources {
		if source.Name == d.Root {
			content, e := readSource(source, d.Path)
			return e == nil && digest(content) == d.Hash
		}
	}
	return false
}
func (s *Service) Edit(ctx context.Context, id, actor string, edit Edit) error {
	d, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}
	if !s.SourceCurrent(d) {
		return ErrConflict
	}
	if err = s.store.Edit(ctx, id, actor, edit); err != nil {
		return err
	}
	if err = s.syncApprovedSkills(ctx); err != nil {
		return err
	}
	return nil
}
