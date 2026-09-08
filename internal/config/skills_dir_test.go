package config

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestEffectiveSkillsDirPrefersNonSerializedRuntimePath(t *testing.T) {
	cfg := &Config{
		SkillsDir:         "configured-skills",
		ResolvedSkillsDir: "resolved-skills-sentinel",
	}

	if got := cfg.EffectiveSkillsDir(); got != cfg.ResolvedSkillsDir {
		t.Fatalf("EffectiveSkillsDir() = %q, want %q", got, cfg.ResolvedSkillsDir)
	}

	jsonData, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	yamlData, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for format, data := range map[string][]byte{"json": jsonData, "yaml": yamlData} {
		if strings.Contains(string(data), cfg.ResolvedSkillsDir) {
			t.Fatalf("%s serialization exposed ResolvedSkillsDir: %s", format, data)
		}
	}
}

func TestEffectiveSkillsDirFallsBackToConfiguredValue(t *testing.T) {
	cfg := &Config{SkillsDir: "configured-skills"}
	if got := cfg.EffectiveSkillsDir(); got != cfg.SkillsDir {
		t.Fatalf("EffectiveSkillsDir() = %q, want %q", got, cfg.SkillsDir)
	}
}
