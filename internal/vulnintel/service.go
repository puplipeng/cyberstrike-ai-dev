package vulnintel

import (
	"context"
	"database/sql/driver"
	"errors"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
)

const syncInterval = 2 * time.Hour
const syncLockID int64 = 739521804

var ErrBusy = errors.New("intelligence sync is already running")
var ErrNotDue = errors.New("source disabled or within the 60-second manual sync cooldown")
var ErrUnavailable = errors.New("intelligence worker is not running")

type Service struct {
	store  *Store
	client *feedClient
	logger *zap.Logger
	mu     sync.Mutex
	active bool
	ctx    context.Context
	cancel context.CancelFunc
	queue  chan []string
	wg     sync.WaitGroup
}

func NewService(store *Store, logger *zap.Logger) *Service {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Service{store: store, logger: logger, client: newFeedClient(os.Getenv("CYBERSTRIKE_NVD_API_KEY")), queue: make(chan []string, 1)}
}
func (s *Service) Store() *Store { return s.store }

func (s *Service) Start(parent context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx != nil {
		return
	}
	s.ctx, s.cancel = context.WithCancel(parent)
	s.wg.Add(1)
	go s.loop()
}
func (s *Service) Close() {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
}
func (s *Service) Trigger(ctx context.Context, source string) error {
	return s.trigger(ctx, source, false)
}

func (s *Service) trigger(ctx context.Context, source string, scheduled bool) error {
	if source != "all" && !sourceValid(source) {
		return errors.New("invalid source")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx == nil || s.ctx.Err() != nil {
		return ErrUnavailable
	}
	if s.active {
		return ErrBusy
	}
	states, err := s.store.Sources(ctx)
	if err != nil {
		return err
	}
	selected := []string{}
	now := time.Now().UTC()
	for _, state := range states {
		if !state.Enabled || (source != "all" && source != state.Source) {
			continue
		}
		interval := time.Minute
		if scheduled {
			interval = sourceInterval(state.Source)
		}
		if state.Status != "running" && state.LastAttempt != nil && now.Sub(*state.LastAttempt) < interval {
			continue
		}
		selected = append(selected, state.Source)
	}
	if len(selected) == 0 {
		return ErrNotDue
	}
	s.active = true
	s.queue <- selected
	return nil
}

func (s *Service) loop() {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	_ = s.trigger(s.ctx, "all", true)
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if err := s.store.DispatchNotifications(s.ctx); err != nil {
				s.logger.Warn("intelligence notification dispatch failed")
			}
			_ = s.trigger(s.ctx, "all", true)
		case sources := <-s.queue:
			s.run(s.ctx, sources)
			s.mu.Lock()
			s.active = false
			s.mu.Unlock()
		}
	}
}

func (s *Service) run(parent context.Context, sources []string) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Minute)
	defer cancel()
	// A session advisory lock also prevents duplicate syncs across app instances.
	conn, err := s.store.db.Conn(ctx)
	if err != nil {
		s.logger.Warn("intelligence lock connection unavailable", zap.Error(err))
		return
	}
	defer conn.Close()
	var locked bool
	if err = conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", syncLockID).Scan(&locked); err != nil || !locked {
		return
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, e := conn.ExecContext(cleanup, "SELECT pg_advisory_unlock($1)", syncLockID); e != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
	}()
	// Only the lock owner can recover an interrupted worker's persisted state.
	if _, err = conn.ExecContext(ctx, `UPDATE vulnerability_intelligence_sources SET status='error',error='Previous sync interrupted; retrying' WHERE status='running'`); err != nil {
		return
	}
	for _, source := range sources {
		if ctx.Err() != nil {
			return
		}
		states, err := s.store.Sources(ctx)
		if err != nil {
			return
		}
		var state SourceState
		for _, item := range states {
			if item.Source == source {
				state = item
				break
			}
		}
		if !state.Enabled {
			continue
		}
		end := time.Now().UTC()
		if err = s.store.begin(ctx, source, end); err != nil {
			return
		}
		count := 0
		version := ""
		if source == "kev" {
			var feed kevFeed
			feed, err = s.client.kev(ctx)
			if err == nil {
				err = s.store.ReplaceKEV(ctx, feed.Records)
				if err != nil {
					err = errors.New("failed to store KEV catalog; previous catalog retained")
				} else {
					count = len(feed.Records)
					version = feed.Version
				}
			}
		} else if source == "epss" {
			var ids map[string]bool
			ids, err = s.store.intelIDs(ctx)
			if err == nil {
				var feed epssFeed
				feed, err = s.client.epss(ctx, ids)
				if err == nil {
					err = s.store.saveEPSS(ctx, feed)
					count = len(feed.Records)
					version = feed.Date + " / model " + feed.Version
				}
			}
		} else {
			initial := state.Checkpoint == nil
			start := end.Add(-30 * 24 * time.Hour)
			if !initial {
				start = state.Checkpoint.Add(-5 * time.Minute)
			}
			save := func(records []NVDRecord) error {
				if e := s.store.SaveNVD(ctx, records); e != nil {
					s.logger.Warn("NVD page storage failed", zap.Error(e))
					return errors.New("failed to store NVD page; checkpoint unchanged")
				}
				return nil
			}
			count, err = s.client.nvd(ctx, start, end, initial, save, func(n int) error { return s.store.progress(ctx, source, n) })
			if err == nil {
				offset := count
				var n int
				n, err = s.client.nvdKEV(ctx, save, func(n int) error { return s.store.progress(ctx, source, offset+n) })
				count += n
			}
			if err == nil {
				var from, to *time.Time
				from, to, err = s.store.legacyNVDWindow(ctx)
				if err == nil && from != nil {
					offset := count
					var n int
					n, err = s.client.nvd(ctx, *from, *to, true, save, func(n int) error { return s.store.progress(ctx, source, offset+n) })
					count += n
					if err == nil {
						from, _, err = s.store.legacyNVDWindow(ctx)
						if err == nil && from != nil {
							err = errors.New("NVD schema refresh incomplete; remaining records will retry")
						}
					}
				}
			}
			// All phases must succeed. KEV backfill never advances the modified-date
			// checkpoint on its own, and committed pages are safe to replay on failure.
			version = "NVD API 2.0 / schema 2"
		}
		finishCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		finishErr := s.store.finish(finishCtx, source, end, count, version, err)
		stop()
		if err != nil {
			s.logger.Warn("vulnerability intelligence sync failed", zap.String("source", source), zap.Error(err))
		} else {
			s.logger.Info("vulnerability intelligence synced", zap.String("source", source), zap.Int("processed", count))
		}
		if finishErr != nil {
			s.logger.Warn("intelligence status write failed", zap.Error(finishErr))
		}
		if e := s.store.DispatchNotifications(ctx); e != nil {
			s.logger.Warn("intelligence notification dispatch failed")
		}
	}
}
