package handler

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
	"gopkg.in/yaml.v3"
)

func TestNormalizeGitHubLeakMonitorConfig(t *testing.T) {
	got, err := normalizeGitHubLeakMonitorConfig(config.GitHubLeakMonitorConfig{
		Keywords: []string{" storage-service ", "storage-service", "vendor.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.IntervalSeconds != 7200 || got.RequestTimeoutSeconds != 45 || got.PerPage != 30 {
		t.Fatalf("unexpected defaults: %+v", got)
	}
	if len(got.Keywords) != 2 || got.Keywords[0] != "storage-service" || got.Keywords[1] != "vendor.example" {
		t.Fatalf("unexpected normalized keywords: %#v", got.Keywords)
	}
}

func TestUpdateGitHubLeakMonitorConfigPersistsNamedRules(t *testing.T) {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte("{}\n"), &document); err != nil {
		t.Fatal(err)
	}
	want := config.GitHubLeakMonitorConfig{
		Enabled: true, Token: "synthetic-token", FingerprintKey: "hex:" + strings.Repeat("ab", 32), Keywords: nil,
		Rules:           []config.GitHubLeakRuleConfig{{Enabled: true, Name: "example-corp-clientid", Keywords: []string{"clientid", "vendor.example"}}},
		IntervalSeconds: 7200, RequestTimeoutSeconds: 45, PerPage: 30,
	}
	updateGitHubLeakMonitorConfig(&document, want)
	data, err := yaml.Marshal(&document)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Monitor config.GitHubLeakMonitorConfig `yaml:"github_leak_monitor"`
	}
	if err = yaml.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Monitor.Rules) != 1 || decoded.Monitor.Rules[0].Name != "example-corp-clientid" ||
		len(decoded.Monitor.Rules[0].Keywords) != 2 || !decoded.Monitor.Rules[0].Enabled ||
		decoded.Monitor.FingerprintKey != want.FingerprintKey {
		t.Fatalf("persisted monitor config = %+v\nyaml=%s", decoded.Monitor, data)
	}
}

func TestNormalizeGitHubLeakMonitorConfigRejectsOversizedANDRule(t *testing.T) {
	tooMany := make([]string, config.MaxGitHubLeakKeywords+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("term-%d", i)
	}
	if _, err := normalizeGitHubLeakMonitorConfig(config.GitHubLeakMonitorConfig{Keywords: tooMany}); err == nil {
		t.Fatal("expected an AND rule with too many terms to be rejected")
	}
	if _, err := normalizeGitHubLeakMonitorConfig(config.GitHubLeakMonitorConfig{
		Keywords: []string{strings.Repeat("a", 130), strings.Repeat("b", 130)},
	}); err == nil {
		t.Fatal("expected an oversized AND rule to be rejected")
	}
}

func TestNormalizeGitHubLeakMonitorConfigRejectsFastPolling(t *testing.T) {
	for _, interval := range []int{30, config.MaxGitHubLeakIntervalSeconds + 1} {
		_, err := normalizeGitHubLeakMonitorConfig(config.GitHubLeakMonitorConfig{
			IntervalSeconds:       interval,
			RequestTimeoutSeconds: 45,
			PerPage:               30,
		})
		if err == nil {
			t.Fatalf("expected interval %d to be rejected", interval)
		}
	}
}

func TestNormalizeGitHubLeakMonitorConfigRequiresEnabledRuleWhenEnabled(t *testing.T) {
	invalid := []config.GitHubLeakMonitorConfig{
		{Enabled: true},
		{Enabled: true, Rules: []config.GitHubLeakRuleConfig{{Enabled: false, Name: "disabled", Keywords: []string{"vendor.example", "clientid"}}}},
	}
	for i, input := range invalid {
		if _, err := normalizeGitHubLeakMonitorConfig(input); err == nil {
			t.Fatalf("enabled config without enabled rule case %d was accepted", i)
		}
	}
	valid := []config.GitHubLeakMonitorConfig{
		{Enabled: true, Keywords: []string{"vendor.example", "clientid"}},
		{Enabled: true, Rules: []config.GitHubLeakRuleConfig{{Enabled: true, Name: "example-corp-clientid", Keywords: []string{"vendor.example", "clientid"}}}},
	}
	for i, input := range valid {
		if _, err := normalizeGitHubLeakMonitorConfig(input); err != nil {
			t.Fatalf("valid enabled rule case %d rejected: %v", i, err)
		}
	}
}

func TestGitHubLeakIntervalEffectiveFallsBackForOutOfRangeStartupConfig(t *testing.T) {
	for _, interval := range []int{0, 30, config.MaxGitHubLeakIntervalSeconds + 1} {
		got := (config.GitHubLeakMonitorConfig{IntervalSeconds: interval}).IntervalSecondsEffective()
		if got != config.DefaultGitHubLeakIntervalSeconds {
			t.Fatalf("effective interval for %d = %d", interval, got)
		}
	}
	if got := (config.GitHubLeakMonitorConfig{IntervalSeconds: config.MaxGitHubLeakIntervalSeconds}).IntervalSecondsEffective(); got != config.MaxGitHubLeakIntervalSeconds {
		t.Fatalf("maximum valid interval = %d", got)
	}
}

func TestNormalizeGitHubLeakMonitorConfigNamedRulesTakePrecedence(t *testing.T) {
	got, err := normalizeGitHubLeakMonitorConfig(config.GitHubLeakMonitorConfig{
		Keywords: []string{"legacy.example", "hidden"},
		Rules: []config.GitHubLeakRuleConfig{
			{Enabled: true, Name: " example-corp-clientid ", Keywords: []string{"vendor.example", "clientid"}},
			{Enabled: false, Name: "access-key", Keywords: []string{"example.com", "ACCESSKEY"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Keywords) != 0 || len(got.Rules) != 2 || got.Rules[0].Name != "example-corp-clientid" ||
		got.Rules[0].Keywords[0] != "clientid" || got.Rules[1].Keywords[0] != "ACCESSKEY" {
		t.Fatalf("normalized named rules = %+v", got)
	}
}

func TestNormalizeGitHubLeakMonitorConfigRejectsAmbiguousRules(t *testing.T) {
	tests := []config.GitHubLeakMonitorConfig{
		{Rules: []config.GitHubLeakRuleConfig{
			{Enabled: true, Name: "Rule", Keywords: []string{"vendor.example", "clientid"}},
			{Enabled: true, Name: "rule", Keywords: []string{"example.com", "accesskey"}},
		}},
		{Rules: []config.GitHubLeakRuleConfig{
			{Enabled: true, Name: "one", Keywords: []string{"vendor.example", "clientid"}},
			{Enabled: true, Name: "two", Keywords: []string{"CLIENTID", "vendor.example"}},
		}},
		{Rules: []config.GitHubLeakRuleConfig{{Enabled: false, Name: "empty"}}},
		{Rules: []config.GitHubLeakRuleConfig{{Enabled: true, Name: "bad\nname", Keywords: []string{"clientid"}}}},
	}
	for i, input := range tests {
		if _, err := normalizeGitHubLeakMonitorConfig(input); err == nil {
			t.Fatalf("ambiguous rule case %d was accepted", i)
		}
	}
}

func TestGitHubLeakMonitorPublicDoesNotContainSecrets(t *testing.T) {
	public := GitHubLeakMonitorPublic{TokenConfigured: true, FingerprintKeyConfigured: true, Rules: []config.GitHubLeakRuleConfig{{Enabled: true, Name: "example-corp-clientid", Keywords: []string{"vendor.example", "clientid"}}}}
	data, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"token"`) || strings.Contains(string(data), `"fingerprint_key"`) || strings.Contains(string(data), "canary") {
		t.Fatalf("public monitor configuration exposed a secret field: %s", data)
	}
	if !strings.Contains(string(data), `"fingerprint_key_configured":true`) || !strings.Contains(string(data), `"rules"`) || !strings.Contains(string(data), `"example-corp-clientid"`) {
		t.Fatalf("public monitor configuration omitted named rules: %s", data)
	}
}
