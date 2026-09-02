package app

import (
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/githubleak"
)

func TestGitHubLeakSettingsUseTwoHourScheduleAndSafeRetrySpacing(t *testing.T) {
	settings := githubLeakSettingsFromConfig(config.GitHubLeakMonitorConfig{
		Keywords:        []string{"storage-service", "vendor.example"},
		IntervalSeconds: 7200,
	})
	if settings.PollIntervalSeconds != 7200 {
		t.Fatalf("poll interval = %d, want 7200", settings.PollIntervalSeconds)
	}
	if settings.IntervalSeconds != githubleak.DefaultIntervalSeconds || settings.IntervalSeconds < githubleak.MinIntervalSeconds {
		t.Fatalf("request retry spacing = %d", settings.IntervalSeconds)
	}
}

func TestGitHubLeakSettingsFingerprintKeyPrecedence(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "environment-unit-token")
	t.Setenv("GITHUB_LEAK_FINGERPRINT_KEY", "environment-unit-fingerprint-key")
	configured := githubLeakSettingsFromConfig(config.GitHubLeakMonitorConfig{
		Token:          "configured-unit-token",
		FingerprintKey: "configured-unit-fingerprint-key",
		Keywords:       []string{"storage-service"},
	})
	if configured.Token != "configured-unit-token" || configured.FingerprintKey != "configured-unit-fingerprint-key" {
		t.Fatalf("configured secret precedence = token:%q fingerprint:%q", configured.Token, configured.FingerprintKey)
	}
	environment := githubLeakSettingsFromConfig(config.GitHubLeakMonitorConfig{Keywords: []string{"storage-service"}})
	if environment.Token != "environment-unit-token" || environment.FingerprintKey != "environment-unit-fingerprint-key" {
		t.Fatalf("environment secret fallback = token:%q fingerprint:%q", environment.Token, environment.FingerprintKey)
	}
}

func TestGitHubLeakSettingsStableFingerprintSurvivesPATRotation(t *testing.T) {
	// Use a mixed-character synthetic token: all-repeated values are deliberately
	// rejected by the detector as placeholders.
	raw := "ghp_" + "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	item := githubleak.SearchItem{
		Repository: "owner/repo", Path: "token.env", BlobSHA: strings.Repeat("a", 40),
		HTMLURL: "https://github.com/owner/repo/blob/main/token.env", Fragments: []string{raw},
	}
	fingerprint := func(token string) string {
		t.Helper()
		settings := githubLeakSettingsFromConfig(config.GitHubLeakMonitorConfig{
			Token: token, FingerprintKey: "stable-configured-fingerprint-key", Keywords: []string{"storage-service"},
		})
		detector, err := githubleak.NewDetector(settings)
		if err != nil {
			t.Fatal(err)
		}
		candidates := detector.Detect("storage-service", item)
		if len(candidates) != 1 {
			t.Fatalf("candidate count = %d", len(candidates))
		}
		return candidates[0].Fingerprint
	}
	if first, second := fingerprint("first-unit-pat"), fingerprint("rotated-unit-pat"); first != second {
		t.Fatal("mapped stable fingerprint key changed across PAT rotation")
	}
}

func TestGitHubLeakSettingsMapsNamedRulesAndLetsThemReplaceLegacy(t *testing.T) {
	settings := githubLeakSettingsFromConfig(config.GitHubLeakMonitorConfig{
		Keywords: []string{"legacy.example", "hidden"},
		Rules: []config.GitHubLeakRuleConfig{
			{Enabled: true, Name: "example-corp-clientid", Keywords: []string{"vendor.example", "clientid"}},
			{Enabled: false, Name: "access-key", Keywords: []string{"example.com", "ACCESSKEY"}},
		},
	})
	normalized, err := settings.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized.Keywords) != 0 || len(normalized.Rules) != 2 || normalized.Rules[0].Name != "example-corp-clientid" {
		t.Fatalf("mapped settings = %+v", normalized)
	}
}
