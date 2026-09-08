package assetmonitor

import (
	"errors"
	"testing"
)

func TestNormalizeRootDomainAndObservationBoundary(t *testing.T) {
	root, err := NormalizeRootDomain("  KUAISHOU.COM. ")
	if err != nil || root != "kuaishou.com" {
		t.Fatalf("NormalizeRootDomain() = %q, %v", root, err)
	}
	for _, invalid := range []string{"com", "api.kuaishou.com", "*.kuaishou.com", "127.0.0.1", "kuaishou..com"} {
		if _, err = NormalizeRootDomain(invalid); !errors.Is(err, ErrValidation) {
			t.Errorf("NormalizeRootDomain(%q) error = %v, want ErrValidation", invalid, err)
		}
	}

	valid := []Observation{
		{Domain: "kuaishou.com", Port: 443},
		{Domain: "API.KUAISHOU.COM.", Port: 80},
		{Host: "https://cdn.kuaishou.com/path", IP: "1.2.3.4", Port: 443},
	}
	for _, input := range valid {
		got, ok := NormalizeObservationForRoot(root, input)
		if !ok || got.Domain == "" || got.Host != got.Domain {
			t.Errorf("valid observation rejected: input=%+v got=%+v ok=%v", input, got, ok)
		}
	}
	invalid := []Observation{
		{Domain: "notkuaishou.com", Port: 443},
		{Domain: "kuaishou.com.evil.test", Port: 443},
		{Host: "1.2.3.4", IP: "1.2.3.4", Port: 443},
		{Domain: "api.kuaishou.com", Port: 70000},
	}
	for _, input := range invalid {
		if got, ok := NormalizeObservationForRoot(root, input); ok {
			t.Errorf("out-of-scope observation accepted: input=%+v got=%+v", input, got)
		}
	}
}

func TestNormalizeRootDomainSupportsIDNA(t *testing.T) {
	got, err := NormalizeRootDomain("食狮.com.cn")
	if err != nil {
		t.Fatal(err)
	}
	if got != "xn--85x722f.com.cn" {
		t.Fatalf("IDNA root = %q", got)
	}
}
