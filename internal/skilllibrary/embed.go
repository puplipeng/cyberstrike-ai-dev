package skilllibrary

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Embedder interface {
	Embed(context.Context, []string) ([][]float32, error)
	Key() string
	Model() string
}
type LocalEmbedder struct {
	base, model, key, revision string
	client                     *http.Client
	slots                      chan struct{}
}

func NewLocalEmbedder(base, model, revision string) (*LocalEmbedder, error) {
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil {
		return nil, ErrInvalid
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "http" || ip == nil || !ip.IsLoopback() || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return nil, fmt.Errorf("embedding URL must be an explicit loopback HTTP origin")
	}
	if strings.TrimSpace(model) == "" || len(model) > 200 || strings.ContainsAny(model, "\r\n\x00") {
		return nil, ErrInvalid
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &LocalEmbedder{base: u.String(), model: model, revision: revision, key: digest(base + "\n" + model + "\n" + revision + "\n1024/chunks-v1"), slots: make(chan struct{}, 2), client: &http.Client{Transport: transport, Timeout: 120 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (e *LocalEmbedder) Key() string   { return e.key }
func (e *LocalEmbedder) Model() string { return e.model }
func validVector(v []float32) bool {
	if len(v) != Dimension {
		return false
	}
	sum := float64(0)
	for _, x := range v {
		if math.IsNaN(float64(x)) || math.IsInf(float64(x), 0) {
			return false
		}
		sum += float64(x) * float64(x)
	}
	return sum > 0
}
func (e *LocalEmbedder) Embed(ctx context.Context, input []string) ([][]float32, error) {
	if len(input) == 0 || len(input) > 8 {
		return nil, ErrInvalid
	}
	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if e.revision != "" {
		if err := e.checkRevision(ctx); err != nil {
			return nil, err
		}
	}
	body, _ := json.Marshal(map[string]any{"model": e.model, "input": input, "truncate": false, "keep_alive": "15m"})
	req, err := http.NewRequestWithContext(ctx, "POST", e.base+"/api/embed", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: local request failed", ErrEmbeddingUnavailable)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		if resp.StatusCode >= 500 || resp.StatusCode == 429 || resp.StatusCode == 404 {
			return nil, fmt.Errorf("%w: HTTP %d", ErrEmbeddingUnavailable, resp.StatusCode)
		}
		return nil, fmt.Errorf("local embedding service returned HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20+1))
	if err != nil || len(raw) > 4<<20 {
		return nil, fmt.Errorf("%w: invalid embedding response", ErrEmbeddingUnavailable)
	}
	var result struct {
		Embeddings [][]float32 `json:"embeddings"`
	}
	if json.Unmarshal(raw, &result) != nil || len(result.Embeddings) != len(input) {
		return nil, fmt.Errorf("%w: invalid embedding count", ErrEmbeddingUnavailable)
	}
	for _, v := range result.Embeddings {
		if !validVector(v) {
			return nil, fmt.Errorf("%w: embedding must contain 1024 finite, nonzero dimensions", ErrEmbeddingUnavailable)
		}
	}
	return result.Embeddings, nil
}

// A local tag may be replaced in Ollama. Refuse to mix vectors from a different
// model revision even when the friendly model name stays the same.
func (e *LocalEmbedder) checkRevision(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", e.base+"/api/tags", nil)
	if err != nil {
		return err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: local model revision unavailable", ErrEmbeddingUnavailable)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%w: local model revision unavailable", ErrEmbeddingUnavailable)
	}
	var data struct {
		Models []struct {
			Name   string `json:"name"`
			Digest string `json:"digest"`
		} `json:"models"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&data) != nil {
		return fmt.Errorf("%w: invalid model list", ErrEmbeddingUnavailable)
	}
	name := e.model
	if !strings.Contains(name, ":") {
		name += ":latest"
	}
	for _, m := range data.Models {
		if m.Name == name && m.Digest == e.revision {
			return nil
		}
	}
	return fmt.Errorf("%w: local model revision changed; update configuration and rebuild the index", ErrEmbeddingUnavailable)
}
