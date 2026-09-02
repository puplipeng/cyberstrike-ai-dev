package vulnintel

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

const sampleCVE = `{"id":"CVE-2026-12345","published":"2026-08-01T10:00:00.000","lastModified":"2026-08-02T10:00:00.000","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"Example vulnerability"}],"metrics":{"cvssMetricV31":[{"type":"Secondary","cvssData":{"version":"3.1","baseScore":4.0,"baseSeverity":"MEDIUM"}},{"type":"Primary","cvssData":{"version":"3.1","baseScore":9.8,"baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/AV:N"}}]},"references":[{"url":"https://example.com/advisory"},{"url":"javascript:alert(1)"},{"url":"https://user:pass@example.com"}],"configurations":[{"operator":"AND","nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:example:product:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0"}]}]}]}`

func sampleNVD(t *testing.T) NVDRecord {
	t.Helper()
	var c nvdCVE
	if err := json.Unmarshal([]byte(sampleCVE), &c); err != nil {
		t.Fatal(err)
	}
	r, err := normalizeNVD(c)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func pageJSON(index, total int, cves ...string) string {
	items := []string{}
	for _, c := range cves {
		items = append(items, `{"cve":`+c+`}`)
	}
	b, _ := json.Marshal(map[string]any{"startIndex": index, "totalResults": total, "resultsPerPage": len(cves), "vulnerabilities": json.RawMessage("[" + strings.Join(items, ",") + "]")})
	return string(b)
}

func TestNormalizeNVDEvidenceAndPrimaryScore(t *testing.T) {
	r := sampleNVD(t)
	if r.Score == nil || *r.Score != 9.8 || r.Severity != "critical" {
		t.Fatalf("wrong primary score: %+v", r)
	}
	if len(r.References) != 1 {
		t.Fatalf("unsafe references retained: %+v", r.References)
	}
	if !strings.Contains(string(r.Configurations), `"operator":"AND"`) || !strings.Contains(string(r.Configurations), `"versionEndExcluding":"2.0"`) {
		t.Fatal("applicability evidence lost")
	}
}

func TestNVDAffectedAndScorePublisherSurviveNormalization(t *testing.T) {
	var c nvdCVE
	if err := json.Unmarshal([]byte(sampleCVE), &c); err != nil {
		t.Fatal(err)
	}
	c.Metrics["cvssMetricV31"][1].Source = "security@example.com"
	c.Affected = json.RawMessage(`[{"source":"cna@example.com","affectedData":[{"vendor":"Example","product":"Gateway","defaultStatus":"unaffected","versions":[{"version":"1.0","lessThan":"2.0","status":"affected","versionType":"semver","changes":[{"at":"1.5","status":"unaffected"}]}],"futureField":{"keep":true}}]}]`)
	r, err := normalizeNVD(c)
	if err != nil || string(r.Affected) != string(c.Affected) || r.CVSSSource != "security@example.com" || r.CVSSType != "Primary" || r.SchemaVersion != nvdSchemaVersion {
		t.Fatalf("evidence lost: %+v %v", r, err)
	}
	c.Metrics = nil
	r, err = normalizeNVD(c)
	if err != nil || r.Score != nil || r.Severity != "unknown" || len(r.Affected) == 0 {
		t.Fatalf("affected product must not imply a CVSS score: %+v %v", r, err)
	}
}

func TestNVDKEVBackfillPaginationHasNoPublicationCutoff(t *testing.T) {
	client := newFeedClient("")
	client.nvdSpacing = 0
	calls, stored, progress := 0, 0, 0
	client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		q := r.URL.Query()
		if !q.Has("hasKev") || q.Has("pubStartDate") || q.Has("lastModStartDate") || q.Get("resultsPerPage") != "2000" {
			t.Fatal("KEV backfill is restricted by a date window")
		}
		cve := strings.ReplaceAll(sampleCVE, "CVE-2026-12345", "CVE-2021-44228")
		if calls == 1 {
			cve = sampleCVE
		}
		index := calls
		calls++
		return response(200, pageJSON(index, 2, cve)), nil
	})
	n, err := client.nvdKEV(context.Background(), func(r []NVDRecord) error { stored += len(r); return nil }, func(n int) error { progress = n; return nil })
	if err != nil || n != 2 || stored != 2 || progress != 2 || calls != 2 {
		t.Fatalf("n=%d stored=%d calls=%d err=%v", n, stored, calls, err)
	}
}

func TestNVDKEVRejectsEmptyDuplicateAndChangedSnapshots(t *testing.T) {
	for _, mode := range []string{"empty", "duplicate", "changed"} {
		t.Run(mode, func(t *testing.T) {
			client := newFeedClient("")
			client.nvdSpacing = 0
			calls := 0
			client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				if mode == "empty" {
					return response(200, pageJSON(0, 0)), nil
				}
				if calls == 1 {
					return response(200, pageJSON(0, 2, sampleCVE)), nil
				}
				total := 2
				if mode == "changed" {
					total = 3
				}
				return response(200, pageJSON(1, total, sampleCVE)), nil
			})
			_, err := client.nvdKEV(context.Background(), func([]NVDRecord) error { return nil }, func(int) error { return nil })
			if err == nil {
				t.Fatal("incomplete KEV backfill reported success")
			}
		})
	}
}
func TestNVDUnknownAndRejectedAreNotLowRisk(t *testing.T) {
	for _, status := range []string{"Awaiting Analysis", "Rejected"} {
		t.Run(status, func(t *testing.T) {
			var c nvdCVE
			json.Unmarshal([]byte(sampleCVE), &c)
			c.Status = status
			if status != "Rejected" {
				c.Metrics = nil
			}
			r, err := normalizeNVD(c)
			if err != nil || r.Score != nil || r.Severity != "unknown" {
				t.Fatalf("got %+v, %v", r, err)
			}
		})
	}
}
func TestNVDPaginationAndWindowParameters(t *testing.T) {
	client := newFeedClient("test-key")
	client.nvdSpacing = 0
	calls := 0
	stored := 0
	client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "services.nvd.nist.gov" || r.Header.Get("apiKey") != "test-key" {
			t.Fatal("wrong request origin or API key header")
		}
		if r.URL.Query().Get("pubStartDate") == "" || r.URL.Query().Get("resultsPerPage") != "2000" {
			t.Fatal("missing time window/pagination")
		}
		index := calls
		calls++
		cve := sampleCVE
		if index == 1 {
			cve = strings.ReplaceAll(cve, "CVE-2026-12345", "CVE-2026-12346")
		}
		return response(200, pageJSON(index, 2, cve)), nil
	})
	n, err := client.nvd(context.Background(), time.Now().Add(-time.Hour), time.Now(), true, func(r []NVDRecord) error { stored += len(r); return nil }, func(int) error { return nil })
	if err != nil || n != 2 || stored != 2 || calls != 2 {
		t.Fatalf("pagination n=%d stored=%d calls=%d err=%v", n, stored, calls, err)
	}
}
func TestNVDFailedPageDoesNotReportSuccess(t *testing.T) {
	for _, body := range []string{`{}`, `{"error":"rate limited"}`, pageJSON(1, 3), pageJSON(1, 1, sampleCVE)} {
		t.Run(body, func(t *testing.T) {
			client := newFeedClient("")
			client.nvdSpacing = 0
			calls := 0
			client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return response(200, pageJSON(0, 3, sampleCVE)), nil
				}
				return response(200, body), nil
			})
			n, err := client.nvd(context.Background(), time.Now().Add(-time.Hour), time.Now(), false, func([]NVDRecord) error { return nil }, func(int) error { return nil })
			if err == nil || n != 1 {
				t.Fatalf("wanted partial failure, n=%d err=%v", n, err)
			}
		})
	}
}
func TestNVDLongIncrementalWindowChunking(t *testing.T) {
	client := newFeedClient("")
	client.nvdSpacing = 0
	calls := 0
	client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		q := r.URL.Query()
		start, _ := parseDate(q.Get("lastModStartDate"))
		end, _ := parseDate(q.Get("lastModEndDate"))
		if start.IsZero() || end.Sub(start) > 120*24*time.Hour {
			t.Fatal("invalid incremental window")
		}
		return response(200, pageJSON(0, 0)), nil
	})
	_, err := client.nvd(context.Background(), time.Now().Add(-250*24*time.Hour), time.Now(), false, func([]NVDRecord) error { return nil }, func(int) error { return nil })
	if err != nil || calls != 3 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}
func TestFeedOriginAndCancellation(t *testing.T) {
	client := newFeedClient("secret")
	calls := 0
	client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return response(200, `{}`), nil })
	if client.get(context.Background(), "http://127.0.0.1/admin", &map[string]any{}) == nil || calls != 0 {
		t.Fatal("arbitrary feed URL accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client.lastNVD = time.Now()
	if !errors.Is(client.get(ctx, nvdURL, &map[string]any{}), context.Canceled) || calls != 0 {
		t.Fatal("canceled rate limit wait made a request")
	}
	initial, _ := http.NewRequest("GET", nvdURL, nil)
	redirect, _ := http.NewRequest("GET", "https://evil.example/", nil)
	if client.http.CheckRedirect(redirect, []*http.Request{initial}) == nil {
		t.Fatal("cross-origin redirect allowed")
	}
}
func sampleKEV() KEVRecord {
	return KEVRecord{ID: "CVE-2026-12345", Title: "Example KEV", Description: "Known exploited", Added: "2026-08-01", Due: "2026-08-20", Action: "Update product", Ransomware: "Unknown"}
}
func TestKEVValidationAndOfficialFallback(t *testing.T) {
	feed := kevFeed{Version: "2026.08.28", Released: "2026-08-28T00:00:00Z", Count: 1, Records: []KEVRecord{sampleKEV()}}
	if err := validateKEV(feed); err != nil {
		t.Fatal(err)
	}
	client := newFeedClient("do-not-send-to-KEV")
	calls := 0
	b, _ := json.Marshal(feed)
	client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("apiKey") != "" {
			t.Fatal("NVD key leaked to KEV")
		}
		if calls == 1 {
			return response(403, "forbidden"), nil
		}
		if r.URL.String() != kevMirrorURL {
			t.Fatal("unofficial mirror")
		}
		return response(200, string(b)), nil
	})
	got, err := client.kev(context.Background())
	if err != nil || got.Count != 1 || calls != 2 {
		t.Fatalf("fallback got %+v, %v", got, err)
	}
	feed.Count = 2
	if validateKEV(feed) == nil {
		t.Fatal("truncated snapshot accepted")
	}
	feed.Records = append(feed.Records, feed.Records[0])
	if validateKEV(feed) == nil {
		t.Fatal("duplicate CVE accepted")
	}
}
func TestRetryDelayBounds(t *testing.T) {
	for _, h := range []string{"-100", "0", "999999", "bad"} {
		d := retryDelay(h, 0)
		if d < time.Second || d > time.Minute {
			t.Fatalf("unbounded delay %s", d)
		}
	}
}

func TestEPSSCSVValidationAndKnownCVESelection(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	body := "#model_version:v4.0.0,score_date:2026-08-28\ncve,epss,percentile\nCVE-2021-44228,0.95,0.999\nCVE-2026-12345,0,0\n"
	f, err := parseEPSS([]byte(body), map[string]bool{"CVE-2026-12345": true}, now)
	if err != nil || f.Total != 2 || len(f.Records) != 1 || f.Records[0].Probability != 0 || f.Version != "v4.0.0" {
		t.Fatalf("parse %+v %v", f, err)
	}
	f, err = parseEPSS([]byte(strings.Replace(body, "score_date:2026-08-28", "score_date:2026-08-28T12:07:20Z", 1)), map[string]bool{"CVE-2021-44228": true}, now)
	if err != nil || f.Date != "2026-08-28" || f.Records[0].Date != f.Date {
		t.Fatalf("official timestamp metadata not normalized: %+v %v", f, err)
	}
	for _, bad := range []string{
		strings.Replace(body, "0.95", "NaN", 1), strings.Replace(body, "0.95", "1.5", 1), strings.Replace(body, "0.999", "-0.1", 1),
		strings.Replace(body, "CVE-2026-12345", "CVE-2021-44228", 1), strings.Replace(body, "2026-08-28", "2026-08-29", 1), strings.Replace(body, "2026-08-28", "2026-08-01", 1),
		"cve,epss,percentile\n", strings.Replace(body, "cve,epss,percentile", "cve,score,percentile", 1),
	} {
		if _, err := parseEPSS([]byte(bad), nil, now); err == nil {
			t.Fatal("malformed EPSS accepted")
		}
	}
}
func TestEPSSDownloadHasNoCredentialsAndChecksGzip(t *testing.T) {
	client := newFeedClient("private-nvd-key")
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write([]byte("#model_version:v4,score_date:" + time.Now().UTC().Format("2006-01-02") + "\ncve,epss,percentile\nCVE-2026-12345,0.2,0.9\n"))
	writer.Close()
	valid := true
	client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != epssURL || r.Header.Get("apiKey") != "" || r.Header.Get("Authorization") != "" {
			t.Fatal("wrong EPSS origin or leaked credentials")
		}
		if valid {
			return response(200, compressed.String()), nil
		}
		return response(200, compressed.String()[:compressed.Len()-6]), nil
	})
	f, err := client.epss(context.Background(), map[string]bool{"CVE-2026-12345": true})
	if err != nil || len(f.Records) != 1 {
		t.Fatalf("download %+v %v", f, err)
	}
	valid = false
	if _, err = client.epss(context.Background(), nil); err == nil {
		t.Fatal("truncated gzip accepted")
	}
}
