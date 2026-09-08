package handler

import (
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/testutil/testpostgres"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func batchChannelTestConfig() *config.Config {
	cfg := &config.Config{AI: config.AIConfig{DefaultChannel: "agnes", Channels: map[string]config.AIChannelConfig{
		"agnes": {Provider: "openai_compatible", Model: "agnes-2.5-flash", BaseURL: "https://agnes.invalid/v1"},
		"glm":   {Provider: "openai_compatible", Model: "glm-5.3-flash", BaseURL: "https://glm.invalid/v4"},
	}}}
	cfg.ApplyDefaultAIChannel()
	return cfg
}

func TestBatchChannelSelectionAndValidation(t *testing.T) {
	cfg := batchChannelTestConfig()
	m := NewBatchTaskManager(zap.NewNop())
	h := &AgentHandler{config: cfg, batchTaskManager: m}
	for _, tc := range []struct {
		channel string
		status  int
		want    string
	}{
		{"glm", 200, "glm"}, {"", 200, "agnes"}, {"deleted-channel", 400, ""},
	} {
		t.Run(tc.channel, func(t *testing.T) {
			body, _ := json.Marshal(map[string]interface{}{"tasks": []string{"synthetic task; do not execute"}, "aiChannelId": tc.channel})
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("POST", "/api/batch-tasks", strings.NewReader(string(body)))
			c.Request.Header.Set("Content-Type", "application/json")
			h.CreateBatchQueue(c)
			if w.Code != tc.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if tc.status != 200 {
				return
			}
			var response struct {
				Queue BatchTaskQueue `json:"queue"`
			}
			_ = json.Unmarshal(w.Body.Bytes(), &response)
			if response.Queue.AIChannelID != tc.want {
				t.Fatalf("channel=%s", response.Queue.AIChannelID)
			}
			runCfg, id, err := h.configForBatchAIChannel(response.Queue.AIChannelID)
			if err != nil || id != tc.want || runCfg.OpenAI.BaseURL != cfg.AI.Channels[tc.want].BaseURL {
				t.Fatalf("wrong execution config: %s %v", id, err)
			}
			if cfg.OpenAI.Model != "agnes-2.5-flash" {
				t.Fatal("shared global config was mutated")
			}
		})
	}
	delete(cfg.AI.Channels, "glm")
	if _, _, err := h.configForBatchAIChannel("glm"); err == nil {
		t.Fatal("deleted selected channel silently fell back")
	}
}

func TestBatchChannelPersistenceAndPausedEdits(t *testing.T) {
	db, err := database.NewDB(testpostgres.DSN(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	m := NewBatchTaskManager(zap.NewNop())
	m.db = db
	q, err := m.CreateBatchQueue("channel test", "", "eino_single", "manual", "", "", nil, 1, nil, []string{"do not execute"}, "glm")
	if err != nil {
		t.Fatal(err)
	}
	// Reload through another manager, as after a server restart.
	reloaded := NewBatchTaskManager(zap.NewNop())
	reloaded.db = db
	q, ok := reloaded.GetBatchQueue(q.ID)
	if !ok || q.AIChannelID != "glm" {
		t.Fatal("channel lost on reload")
	}
	for _, list := range []func() ([]*database.BatchTaskQueueRow, error){db.GetAllBatchQueues, func() ([]*database.BatchTaskQueueRow, error) { return db.ListBatchQueues(10, 0, "all", "") }} {
		rows, err := list()
		if err != nil || len(rows) != 1 || rows[0].AIChannelID.String != "glm" {
			t.Fatalf("list failed: %v", err)
		}
	}
	reloaded.UpdateQueueStatus(q.ID, BatchQueueStatusPaused)
	if err := reloaded.UpdateQueueMetadata(q.ID, "renamed", "", "", nil); err != nil {
		t.Fatal(err)
	}
	row, err := db.GetBatchQueue(q.ID)
	if err != nil || row.AIChannelID.String != "glm" {
		t.Fatal("unrelated metadata edit cleared channel")
	}
	reloaded.TryMarkQueueExecutor(q.ID)
	if err := reloaded.UpdateQueueMetadata(q.ID, "renamed", "", "", nil, "agnes"); err == nil {
		t.Fatal("edited channel while executor was active")
	}
	reloaded.UnmarkQueueExecutor(q.ID)
	if err := reloaded.UpdateQueueMetadata(q.ID, "renamed", "", "", nil, "agnes"); err != nil {
		t.Fatal(err)
	}
	row, err = db.GetBatchQueue(q.ID)
	if err != nil || row.AIChannelID.String != "agnes" || row.Status != "paused" {
		t.Fatal("paused edit was not persisted")
	}
	// Persistence failure must not report a successful in-memory channel change.
	_ = db.Close()
	if err := reloaded.UpdateQueueMetadata(q.ID, "bad", "", "", nil, "glm"); err == nil {
		t.Fatal("DB failure hidden")
	}
	q, _ = reloaded.GetBatchQueue(q.ID)
	if q.AIChannelID != "agnes" {
		t.Fatal("memory diverged after failed save")
	}
}

func TestNormalizeBatchQueueConcurrency(t *testing.T) {
	if got := normalizeBatchQueueConcurrency(0); got != DefaultBatchQueueConcurrency {
		t.Fatalf("expected default %d, got %d", DefaultBatchQueueConcurrency, got)
	}
	if got := normalizeBatchQueueConcurrency(99); got != MaxBatchQueueConcurrency {
		t.Fatalf("expected max %d, got %d", MaxBatchQueueConcurrency, got)
	}
}

func TestBatchQueueKeepsApprovalDecisionMadeBeforeStart(t *testing.T) {
	t.Parallel()
	m := NewBatchTaskManager(zap.NewNop())
	requested := &HITLRequest{
		Enabled:        false,
		Mode:           "off",
		Reviewer:       "human",
		SensitiveTools: []string{" tool_a ", "TOOL_A", "tool_b"},
		TimeoutSeconds: -1,
	}
	queue, err := m.CreateBatchQueue("scan", "", "eino_single", "manual", "", "", nil, 1, requested, []string{"scan asset"})
	if err != nil {
		t.Fatalf("CreateBatchQueue: %v", err)
	}
	if queue.HITL == nil {
		t.Fatal("explicit approval decision should be stored on the queue")
	}
	if queue.HITL.Enabled || queue.HITL.Mode != "off" {
		t.Fatalf("expected explicit off, got %+v", queue.HITL)
	}
	if queue.HITL.TimeoutSeconds != 0 {
		t.Fatalf("negative timeout should normalize to zero, got %d", queue.HITL.TimeoutSeconds)
	}
	if len(queue.HITL.SensitiveTools) != 2 {
		t.Fatalf("expected normalized unique tools, got %#v", queue.HITL.SensitiveTools)
	}

	restored := decodeBatchQueueHITL(encodeBatchQueueHITL(queue.HITL))
	if restored == nil || restored.Enabled || restored.Mode != "off" {
		t.Fatalf("stored approval decision did not round-trip: %+v", restored)
	}
}

func TestClaimNextPendingTaskParallel(t *testing.T) {
	m := NewBatchTaskManager(zap.NewNop())
	queue, err := m.CreateBatchQueue("test", "", "eino_single", "manual", "", "", nil, 3, nil, []string{"a", "b", "c"})
	if err != nil {
		t.Fatalf("CreateBatchQueue: %v", err)
	}
	m.UpdateQueueStatus(queue.ID, BatchQueueStatusRunning)

	t1, ok1 := m.ClaimNextPendingTask(queue.ID)
	t2, ok2 := m.ClaimNextPendingTask(queue.ID)
	if !ok1 || !ok2 || t1.ID == t2.ID {
		t.Fatalf("expected two distinct claims, got ok1=%v ok2=%v t1=%v t2=%v", ok1, ok2, t1, t2)
	}
	if t1.Status != BatchTaskStatusRunning || t2.Status != BatchTaskStatusRunning {
		t.Fatalf("claimed tasks should be running")
	}
	t3, ok3 := m.ClaimNextPendingTask(queue.ID)
	if !ok3 {
		t.Fatal("expected third claim")
	}
	_, ok4 := m.ClaimNextPendingTask(queue.ID)
	if ok4 {
		t.Fatal("expected no fourth pending task")
	}
	_ = t3
}

func TestBatchQueueExecutionShouldStop(t *testing.T) {
	t.Parallel()
	if !batchQueueExecutionShouldStop(nil, false) {
		t.Fatal("expected stop when queue missing")
	}
	if !batchQueueExecutionShouldStop(nil, true) {
		t.Fatal("expected stop when queue is nil but exists=true")
	}
	q := &BatchTaskQueue{Status: BatchQueueStatusRunning}
	if batchQueueExecutionShouldStop(q, true) {
		t.Fatal("expected continue when running")
	}
	q.Status = BatchQueueStatusCancelled
	if !batchQueueExecutionShouldStop(q, true) {
		t.Fatal("expected stop when cancelled")
	}
}

func TestBatchSubTaskConversationMetaKeepsQueueRole(t *testing.T) {
	t.Parallel()

	meta := batchSubTaskConversationMeta(nil, &BatchTaskQueue{Role: " 渗透测试 "})
	if meta.Source != "batch_task" {
		t.Fatalf("expected batch_task source, got %q", meta.Source)
	}
	if meta.RoleName != "渗透测试" {
		t.Fatalf("expected queue role to be stored on child conversation, got %q", meta.RoleName)
	}
}

func TestDeleteQueueBlockedWhileExecutorActive(t *testing.T) {
	t.Parallel()
	m := NewBatchTaskManager(zap.NewNop())
	queue, err := m.CreateBatchQueue("test", "", "eino_single", "manual", "", "", nil, 1, nil, []string{"hello"})
	if err != nil {
		t.Fatalf("CreateBatchQueue: %v", err)
	}
	if !m.TryMarkQueueExecutor(queue.ID) {
		t.Fatal("expected to mark executor")
	}
	m.UpdateQueueStatus(queue.ID, BatchQueueStatusCancelled)

	err = m.DeleteQueue(queue.ID)
	if !errors.Is(err, ErrBatchQueueExecutorActive) {
		t.Fatalf("expected ErrBatchQueueExecutorActive, got %v", err)
	}
	if _, ok := m.GetBatchQueue(queue.ID); !ok {
		t.Fatal("queue should still exist while executor active")
	}

	m.UnmarkQueueExecutor(queue.ID)
	if err := m.DeleteQueue(queue.ID); err != nil {
		t.Fatalf("expected delete after executor unmarked, got %v", err)
	}
	if _, ok := m.GetBatchQueue(queue.ID); ok {
		t.Fatal("queue should be deleted")
	}
}

func TestDeleteQueueBlockedWhileRunning(t *testing.T) {
	t.Parallel()
	m := NewBatchTaskManager(zap.NewNop())
	queue, err := m.CreateBatchQueue("test", "", "eino_single", "manual", "", "", nil, 1, nil, []string{"hello"})
	if err != nil {
		t.Fatalf("CreateBatchQueue: %v", err)
	}
	m.UpdateQueueStatus(queue.ID, BatchQueueStatusRunning)

	err = m.DeleteQueue(queue.ID)
	if !errors.Is(err, ErrBatchQueueStillRunning) {
		t.Fatalf("expected ErrBatchQueueStillRunning, got %v", err)
	}
}

func TestTryMarkQueueExecutorDedupes(t *testing.T) {
	t.Parallel()
	m := NewBatchTaskManager(zap.NewNop())
	if !m.TryMarkQueueExecutor("q-1") {
		t.Fatal("first mark should succeed")
	}
	if m.TryMarkQueueExecutor("q-1") {
		t.Fatal("second mark should fail")
	}
	m.UnmarkQueueExecutor("q-1")
	if !m.TryMarkQueueExecutor("q-1") {
		t.Fatal("mark after unmark should succeed")
	}
}
