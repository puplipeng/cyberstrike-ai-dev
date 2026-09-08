package app

import (
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/config"
)

func TestResolveRuntimeSkillsDirPersistsDefaultForRunners(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg := &config.Config{}

	want := filepath.Join(filepath.Dir(configPath), "skills")
	if got := resolveRuntimeSkillsDir(cfg, configPath); got != want {
		t.Fatalf("resolveRuntimeSkillsDir() = %q, want %q", got, want)
	}
	if got := cfg.EffectiveSkillsDir(); got != want {
		t.Fatalf("EffectiveSkillsDir() = %q, want runtime path %q", got, want)
	}
	if cfg.SkillsDir != "" {
		t.Fatalf("configured SkillsDir was mutated to %q", cfg.SkillsDir)
	}
}
