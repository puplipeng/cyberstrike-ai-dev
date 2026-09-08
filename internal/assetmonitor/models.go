// Package assetmonitor discovers project assets on a schedule and records the
// observations that made an asset new to a monitor. Provider credentials and
// raw provider responses are deliberately never persisted.
package assetmonitor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	ProviderQuake          = "quake"
	DefaultIntervalMinutes = 1440
	DefaultMaxResults      = 200
	MinIntervalMinutes     = 60
	MaxIntervalMinutes     = 10080
	MinMaxResults          = 1
	MaxMaxResults          = 1000

	MonitorStatusIdle     = "idle"
	MonitorStatusQueued   = "queued"
	MonitorStatusRunning  = "running"
	MonitorStatusSuccess  = "success"
	MonitorStatusPartial  = "partial"
	MonitorStatusError    = "error"
	MonitorStatusDisabled = "disabled"

	RunStatusQueued    = "queued"
	RunStatusRunning   = "running"
	RunStatusSuccess   = "success"
	RunStatusPartial   = "partial"
	RunStatusError     = "error"
	RunStatusCancelled = "cancelled"

	RunTriggerManual    = "manual"
	RunTriggerScheduled = "scheduled"

	RunAssetStateNew  = "new"
	RunAssetStateSeen = "seen"
)

var (
	ErrNotFound     = errors.New("asset monitor not found")
	ErrBusy         = errors.New("asset monitor is already queued or running")
	ErrUnconfigured = errors.New("asset monitor provider is not configured")
	ErrValidation   = errors.New("invalid asset monitor input")
	ErrUnavailable  = errors.New("asset monitor service is unavailable")
	ErrConflict     = errors.New("asset monitor already exists")
)

// Monitor is a project-scoped root-domain monitor. Query is generated from
// RootDomain rather than accepting arbitrary provider syntax from an API user.
type Monitor struct {
	ID                 string `json:"id"`
	ProjectID          string `json:"project_id"`
	OwnerUserID        string `json:"owner_user_id"`
	Name               string `json:"name"`
	RootDomain         string `json:"root_domain"`
	Provider           string `json:"provider"`
	ProviderConfigured bool   `json:"provider_configured"`
	Query              string `json:"query"`
	// CronExpr is retained only for wire compatibility with experimental clients.
	// IntervalMinutes is the authoritative schedule.
	CronExpr        string     `json:"cron_expr,omitempty"`
	IntervalMinutes int        `json:"interval_minutes"`
	MaxResults      int        `json:"max_results"`
	Enabled         bool       `json:"enabled"`
	NextRunAt       *time.Time `json:"next_run_at,omitempty"`
	LastRunAt       *time.Time `json:"last_run_at,omitempty"`
	LastStatus      string     `json:"last_status"`
	LastError       string     `json:"last_error"`
	LastSeenCount   int        `json:"last_seen_count"`
	LastNewCount    int        `json:"last_new_count"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type CreateMonitorInput struct {
	ProjectID       string `json:"project_id"`
	OwnerUserID     string `json:"owner_user_id"`
	Name            string `json:"name"`
	RootDomain      string `json:"root_domain"`
	Provider        string `json:"provider,omitempty"`
	CronExpr        string `json:"cron_expr,omitempty"`
	IntervalMinutes int    `json:"interval_minutes,omitempty"`
	MaxResults      int    `json:"max_results,omitempty"`
	Enabled         *bool  `json:"enabled,omitempty"`
}

// UpdateMonitorInput uses pointers so false and an omitted value remain
// distinguishable at the HTTP boundary.
type UpdateMonitorInput struct {
	Name            *string `json:"name,omitempty"`
	RootDomain      *string `json:"root_domain,omitempty"`
	Provider        *string `json:"provider,omitempty"`
	CronExpr        *string `json:"cron_expr,omitempty"`
	IntervalMinutes *int    `json:"interval_minutes,omitempty"`
	MaxResults      *int    `json:"max_results,omitempty"`
	Enabled         *bool   `json:"enabled,omitempty"`
}

type Run struct {
	ID            string     `json:"id"`
	MonitorID     string     `json:"monitor_id"`
	ProjectID     string     `json:"project_id"`
	Trigger       string     `json:"trigger"`
	TriggeredBy   string     `json:"triggered_by,omitempty"`
	Status        string     `json:"status"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
	TotalCount    int        `json:"total_count"`
	SeenCount     int        `json:"seen_count"`
	NewCount      int        `json:"new_count"`
	CreatedCount  int        `json:"created_count"`
	UpdatedCount  int        `json:"updated_count"`
	SkippedCount  int        `json:"skipped_count"`
	ConflictCount int        `json:"conflict_count"`
	Error         string     `json:"error"`
	CreatedAt     time.Time  `json:"created_at"`
}

type RunAsset struct {
	RunID      string    `json:"run_id"`
	MonitorID  string    `json:"monitor_id"`
	AssetID    string    `json:"asset_id"`
	State      string    `json:"state"`
	ObservedAt time.Time `json:"observed_at"`
	Host       string    `json:"host"`
	IP         string    `json:"ip"`
	Port       int       `json:"port"`
	Domain     string    `json:"domain"`
	Protocol   string    `json:"protocol"`
	Title      string    `json:"title"`
	Server     string    `json:"server"`
}

type RunListOptions struct {
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

type RunListResult struct {
	Items []Run `json:"items"`
	Total int   `json:"total"`
}

type RunAssetListOptions struct {
	State  string `json:"state,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	Offset int    `json:"offset,omitempty"`
}

type RunAssetListResult struct {
	Items []RunAsset `json:"items"`
	Total int        `json:"total"`
}

// Observation is a normalized provider result. Service applies root-domain
// validation again before any Observation reaches Store, even for custom
// Provider implementations.
type Observation struct {
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Domain   string `json:"domain"`
	Protocol string `json:"protocol"`
	Title    string `json:"title"`
	Server   string `json:"server"`
	Country  string `json:"country"`
	Province string `json:"province"`
	City     string `json:"city"`
}

type SearchRequest struct {
	RootDomain string
	Query      string
	Page       int
	PageSize   int
}

type SearchPage struct {
	Observations []Observation
	Total        int
	RawCount     int
	Skipped      int
	HasMore      bool
}

type Provider interface {
	Name() string
	Search(context.Context, SearchRequest) (SearchPage, error)
}

type configuredProvider interface{ Configured() bool }

func providerConfigured(provider Provider) bool {
	if provider == nil {
		return false
	}
	configured, ok := provider.(configuredProvider)
	return !ok || configured.Configured()
}

func validationErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrValidation, fmt.Sprintf(format, args...))
}

func normalizePage(limit, offset int) (int, int, error) {
	if limit == 0 {
		limit = 25
	}
	if limit < 1 || limit > 100 || offset < 0 || offset > 10_000_000 {
		return 0, 0, validationErrorf("invalid pagination")
	}
	return limit, offset, nil
}

func normalizeRunAssetState(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value != "" && value != RunAssetStateNew && value != RunAssetStateSeen {
		return "", validationErrorf("state must be new or seen")
	}
	return value, nil
}
