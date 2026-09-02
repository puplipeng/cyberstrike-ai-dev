package knowledge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"cyberstrike-ai/internal/codexbridge"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/llm"
	"cyberstrike-ai/internal/mcp"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/retriever"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

func TestBuildKnowledgeRetrieveChain_Compile(t *testing.T) {
	r := NewRetriever(nil, nil, &RetrievalConfig{TopK: 3, SimilarityThreshold: 0.5}, zap.NewNop())
	_, err := BuildKnowledgeRetrieveChain(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBuildKnowledgeRetrieveChain_NilRetriever(t *testing.T) {
	_, err := BuildKnowledgeRetrieveChain(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil retriever")
	}
}

type knowledgeRetrieverFixture func(context.Context, string, ...retriever.Option) ([]*schema.Document, error)

func (f knowledgeRetrieverFixture) Retrieve(ctx context.Context, query string, opts ...retriever.Option) ([]*schema.Document, error) {
	return f(ctx, query, opts...)
}

type knowledgeRewriteFixture struct {
	text  string
	err   error
	calls int
}

func (m *knowledgeRewriteFixture) Generate(context.Context, []*schema.Message, ...model.Option) (*schema.Message, error) {
	m.calls++
	return schema.AssistantMessage(m.text, nil), m.err
}

func (*knowledgeRewriteFixture) Stream(context.Context, []*schema.Message, ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return nil, errors.New("unexpected streaming model call")
}

func (*knowledgeRewriteFixture) BindTools([]*schema.ToolInfo) error { return nil }

func TestWireKnowledgeRetrievalDoesNotRequireChatModelByDefault(t *testing.T) {
	// An empty Codex model cannot be constructed. Default retrieval must still
	// start without creating it, and every entry point must keep post-processing.
	r := NewRetriever(nil, nil, &RetrievalConfig{}, zap.NewNop())
	if err := WireRetrieverPipeline(context.Background(), r, &config.OpenAIConfig{Provider: codexbridge.Provider}); err != nil {
		t.Fatal(err)
	}
	pipeline, ok := r.activeEinoRetriever().(*knowledgePipelineRetriever)
	if !ok {
		t.Fatal("direct retrieval bypassed output post-processing")
	}
	if _, ok := pipeline.inner.(*VectorEinoRetriever); !ok {
		t.Fatalf("default retrieval unexpectedly uses query rewrite: %T", pipeline.inner)
	}
	unwired := NewRetriever(nil, nil, nil, zap.NewNop())
	if _, ok := unwired.activeEinoRetriever().(*knowledgePipelineRetriever); !ok {
		t.Fatal("unwired retrieval bypassed output post-processing")
	}
}

func TestKnowledgeRewriteModelUsesCodexAccountAdapter(t *testing.T) {
	m, err := buildKnowledgeRewriteModel(context.Background(), config.OpenAIConfig{
		Provider: codexbridge.Provider, Model: "gpt-5.4", MaxCompletionTokens: 32768,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.(*llm.AgenticChatModelAdapter); !ok {
		t.Fatalf("Codex query rewriting selected an API-key HTTP model: %T", m)
	}
}

func TestKnowledgeRewriteHTTPModelUsesSingleOutputLimit(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured int
		override   int
		want       int
	}{
		{"default rewrite ceiling", 4096, 0, 1024},
		{"remaining budget is smaller", 4096, 128, 128},
		{"larger override cannot raise rewrite ceiling", 4096, 2048, 1024},
		{"smaller channel limit remains effective", 64, 128, 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observed := make(chan []byte, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method != http.MethodPost || req.URL.Path != "/v1/chat/completions" {
					http.Error(w, "unexpected fixture request", http.StatusNotFound)
					return
				}
				body, err := io.ReadAll(req.Body)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				observed <- body
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"id":"fixture","object":"chat.completion","created":1,"model":"rewrite-fixture","choices":[{"index":0,"message":{"role":"assistant","content":"[]"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`)
			}))
			defer server.Close()
			m, err := buildKnowledgeRewriteModel(context.Background(), config.OpenAIConfig{
				Provider: "openai", APIKey: "fixture-key", BaseURL: server.URL + "/v1",
				Model: "rewrite-fixture", MaxCompletionTokens: tc.configured,
			})
			if err != nil {
				t.Fatal(err)
			}
			var opts []model.Option
			if tc.override > 0 {
				opts = append(opts, model.WithMaxTokens(tc.override))
			}
			if _, err := m.Generate(context.Background(), []*schema.Message{schema.UserMessage("rewrite output budget fixture")}, opts...); err != nil {
				t.Fatal(err)
			}
			var payload map[string]json.RawMessage
			if err := json.Unmarshal(<-observed, &payload); err != nil {
				t.Fatal(err)
			}
			if _, exists := payload["max_tokens"]; exists {
				t.Fatal("rewrite request contains conflicting legacy max_tokens")
			}
			var limit int
			if err := json.Unmarshal(payload["max_completion_tokens"], &limit); err != nil {
				t.Fatal(err)
			}
			if limit != tc.want {
				t.Fatalf("rewrite output limit = %d, want %d", limit, tc.want)
			}
			if !strings.Contains(string(payload["messages"]), "rewrite output budget fixture") {
				t.Fatal("rewrite query was lost")
			}
		})
	}
}

func TestKnowledgeRewriteSetupFailureKeepsVectorPipeline(t *testing.T) {
	r := NewRetriever(nil, nil, &RetrievalConfig{MultiQuery: config.MultiQueryConfig{Enabled: true}}, zap.NewNop())
	// Missing model name fails the Codex constructor locally, before any bridge
	// or provider is contacted. Knowledge retrieval must remain available.
	if err := WireRetrieverPipeline(context.Background(), r, &config.OpenAIConfig{Provider: codexbridge.Provider}); err != nil {
		t.Fatal(err)
	}
	pipeline := r.activeEinoRetriever().(*knowledgePipelineRetriever)
	if _, ok := pipeline.inner.(*VectorEinoRetriever); !ok {
		t.Fatalf("failed rewrite setup left an unusable pipeline: %T", pipeline.inner)
	}
}

func TestKnowledgeRerankRequiresExplicitConfiguration(t *testing.T) {
	r := NewRetriever(nil, nil, &RetrievalConfig{}, zap.NewNop())
	// A main-chat API key must not implicitly create a rerank request endpoint.
	chatCfg := &config.OpenAIConfig{APIKey: "fixture-key", BaseURL: "https://example.invalid/v1"}
	r.SetDocumentReranker(NopDocumentReranker{})
	if err := WireRetrieverPipeline(context.Background(), r, chatCfg); err != nil {
		t.Fatal(err)
	}
	if r.documentReranker() != nil {
		t.Fatal("empty rerank settings borrowed main-channel credentials or kept stale reranker")
	}
	r.config.Rerank.Model = "explicit-fixture-reranker"
	if err := WireRetrieverPipeline(context.Background(), r, chatCfg); err != nil {
		t.Fatal(err)
	}
	if r.documentReranker() == nil {
		t.Fatal("explicit rerank settings no longer allow main-channel key fallback")
	}
	// Constructor checks only: no Rerank/provider method is called in this test.
}

func TestKnowledgeQueryRewritePreservesOptionsAndOriginalQuery(t *testing.T) {
	type observation struct {
		query string
		topK  int
		dsl   map[string]any
	}
	observed := make(chan observation, 4)
	inner := knowledgeRetrieverFixture(func(_ context.Context, query string, opts ...retriever.Option) ([]*schema.Document, error) {
		options := retriever.GetCommonOptions(nil, opts...)
		obs := observation{query: query, dsl: options.DSLInfo}
		if options.TopK != nil {
			obs.topK = *options.TopK
		}
		observed <- obs
		return []*schema.Document{doc(query, "content "+query, 0.8)}, nil
	})
	rewrite := &knowledgeRewriteFixture{text: `["alternative","original","alternative","third","fourth"]`}
	r := &knowledgeQueryRewriteRetriever{inner: inner, model: rewrite, maxQueries: 3}
	dsl := map[string]any{DSLRiskType: "SQL注入", DSLSimilarityThreshold: 0.9, DSLSubIndexFilter: "web"}
	docs, err := r.Retrieve(context.Background(), "original", retriever.WithTopK(2), retriever.WithDSLInfo(dsl))
	if err != nil {
		t.Fatal(err)
	}
	if rewrite.calls != 1 || len(docs) != 3 {
		t.Fatalf("calls=%d docs=%d, want one rewrite and three unique queries", rewrite.calls, len(docs))
	}
	close(observed)
	queries := map[string]bool{}
	for obs := range observed {
		queries[obs.query] = true
		if obs.topK != 2 || !reflect.DeepEqual(obs.dsl, dsl) {
			t.Fatalf("retrieval options were lost for %q: %#v", obs.query, obs)
		}
	}
	if !reflect.DeepEqual(queries, map[string]bool{"original": true, "alternative": true, "third": true}) {
		t.Fatalf("original query not retained or fan-out cap exceeded: %v", queries)
	}
}

func TestKnowledgeRewriteFailureFallsBackWithFiltersAndBudget(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		err  error
	}{
		{name: "provider error", err: errors.New("unavailable")},
		{name: "malformed rewrite", text: "not a JSON array"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			dsl := map[string]any{DSLRiskType: "XSS", DSLSimilarityThreshold: 0.85, DSLSubIndexFilter: "web"}
			inner := knowledgeRetrieverFixture(func(_ context.Context, query string, opts ...retriever.Option) ([]*schema.Document, error) {
				calls++
				options := retriever.GetCommonOptions(nil, opts...)
				if query != "original" || !reflect.DeepEqual(options.DSLInfo, dsl) {
					t.Fatalf("fallback broadened the original retrieval: query=%q options=%#v", query, options)
				}
				return []*schema.Document{doc("1", "abc", 0.9), doc("2", "def", 0.8)}, nil
			})
			rewrite := &knowledgeRewriteFixture{text: tc.text, err: tc.err}
			base := NewRetriever(nil, nil, &RetrievalConfig{TopK: 5, PostRetrieve: config.PostRetrieveConfig{MaxContextChars: 4}}, zap.NewNop())
			pipeline := newKnowledgePipelineRetriever(&knowledgeQueryRewriteRetriever{inner: inner, model: rewrite, maxQueries: 4}, base)
			docs, err := pipeline.Retrieve(context.Background(), "original", retriever.WithDSLInfo(dsl))
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 || rewrite.calls != 1 || len(docs) != 1 || docs[0].ID != "1" {
				t.Fatalf("fallback retried rewrite or bypassed budget: vectorCalls=%d rewriteCalls=%d docs=%v", calls, rewrite.calls, docs)
			}
		})
	}
}

func TestKnowledgeQueryRewriteSingleQuerySkipsModelAndCancellation(t *testing.T) {
	calls := 0
	inner := knowledgeRetrieverFixture(func(context.Context, string, ...retriever.Option) ([]*schema.Document, error) {
		calls++
		return nil, nil
	})
	rewrite := &knowledgeRewriteFixture{}
	r := &knowledgeQueryRewriteRetriever{inner: inner, model: rewrite, maxQueries: 1}
	if _, err := r.Retrieve(context.Background(), "query"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || rewrite.calls != 0 {
		t.Fatalf("one-query limit must not spend a rewrite call: vector=%d rewrite=%d", calls, rewrite.calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Retrieve(ctx, "query"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled retrieval was not stopped: %v", err)
	}
	if calls != 1 || rewrite.calls != 0 {
		t.Fatal("canceled query still called a retriever or model")
	}
}

func TestKnowledgeQueryRewriteKeepsResultsWhenAnOptionalVariantFails(t *testing.T) {
	inner := knowledgeRetrieverFixture(func(_ context.Context, q string, _ ...retriever.Option) ([]*schema.Document, error) {
		switch q {
		case "broken":
			return nil, errors.New("variant failed")
		case "alternative":
			return []*schema.Document{doc("same", "better content", 0.9)}, nil
		default:
			return []*schema.Document{doc("same", "original content", 0.8)}, nil
		}
	})
	r := &knowledgeQueryRewriteRetriever{inner: inner, model: &knowledgeRewriteFixture{text: `["alternative","broken"]`}, maxQueries: 3}
	docs, err := r.Retrieve(context.Background(), "original")
	if err != nil || len(docs) != 1 || docs[0].Content != "better content" {
		t.Fatalf("valid results were lost or duplicated: docs=%v err=%v", docs, err)
	}
}

func TestKnowledgePipelineHonorsConfiguredTopK(t *testing.T) {
	base := NewRetriever(nil, nil, &RetrievalConfig{TopK: 1}, zap.NewNop())
	inner := knowledgeRetrieverFixture(func(context.Context, string, ...retriever.Option) ([]*schema.Document, error) {
		return []*schema.Document{doc("1", "one", 0.9), doc("2", "two", 0.8)}, nil
	})
	p := newKnowledgePipelineRetriever(inner, base)
	docs, err := p.Retrieve(context.Background(), "query")
	if err != nil || len(docs) != 1 {
		t.Fatalf("configured TopK ignored: docs=%v err=%v", docs, err)
	}
	docs, err = p.Retrieve(context.Background(), "query", retriever.WithTopK(2))
	if err != nil || len(docs) != 2 {
		t.Fatalf("explicit TopK override ignored: docs=%v err=%v", docs, err)
	}
}

func TestKnowledgeToolInheritsConfiguredTopK(t *testing.T) {
	base := NewRetriever(nil, nil, &RetrievalConfig{TopK: 1}, zap.NewNop())
	inner := knowledgeRetrieverFixture(func(context.Context, string, ...retriever.Option) ([]*schema.Document, error) {
		first := doc("1", "first-document-body", 0.9)
		second := doc("2", "second-document-body", 0.8)
		first.MetaData[metaKBChunkIndex] = 0
		second.MetaData[metaKBChunkIndex] = 1
		return []*schema.Document{first, second}, nil
	})
	base.pipeline = newKnowledgePipelineRetriever(inner, base)
	server := mcp.NewServer(zap.NewNop())
	RegisterKnowledgeTool(server, base, nil, zap.NewNop())
	result, _, err := server.CallTool(context.Background(), "search_knowledge_base", map[string]interface{}{"query": "fixture"})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("fixture knowledge tool failed: result=%v err=%v", result, err)
	}
	text := mcp.ToolResultPlainText(result)
	if !strings.Contains(text, "first-document-body") || strings.Contains(text, "second-document-body") {
		t.Fatalf("tool entry point overrode configured TopK: %s", text)
	}
}

func TestKnowledgeFallbackHonorsTokenBudget(t *testing.T) {
	tokenModel := installKnowledgeByteTokenizer(t)
	base := NewRetriever(nil, nil, &RetrievalConfig{PostRetrieve: config.PostRetrieveConfig{MaxContextTokens: 4}}, zap.NewNop())
	base.wireOpenAI = &config.OpenAIConfig{Model: tokenModel}
	inner := knowledgeRetrieverFixture(func(context.Context, string, ...retriever.Option) ([]*schema.Document, error) {
		return []*schema.Document{doc("1", "abc", 0.9), doc("2", "def", 0.8)}, nil
	})
	pipeline := newKnowledgePipelineRetriever(&knowledgeQueryRewriteRetriever{
		inner: inner, model: &knowledgeRewriteFixture{err: errors.New("fixture rewrite failure")}, maxQueries: 4,
	}, base)
	docs, err := pipeline.Retrieve(context.Background(), "query")
	if err != nil || len(docs) != 1 || docs[0].ID != "1" {
		t.Fatalf("query-rewrite fallback ignored token budget: docs=%v err=%v", docs, err)
	}
}

func TestKnowledgeVectorSQLBindsEachOptionalFilter(t *testing.T) {
	for _, riskType := range []string{"", " SQL注入 "} {
		for _, subIndex := range []string{"", " WEB "} {
			t.Run(fmt.Sprintf("risk=%s/sub=%s", riskType, subIndex), func(t *testing.T) {
				q, args := knowledgeVectorSelectSQL("[0.1,0.2]", riskType, subIndex, "bge-m3", 1024, 20)
				want := []interface{}{"[0.1,0.2]"}
				if riskType != "" {
					want = append(want, "SQL注入")
					clause := fmt.Sprintf("LOWER(TRIM(i.category)) = LOWER($%d::text)", len(want))
					if !strings.Contains(q, clause) {
						t.Fatalf("risk filter bound to wrong parameter: %s", q)
					}
				}
				if subIndex != "" {
					want = append(want, "web")
					clause := fmt.Sprintf("POSITION(',' || $%d::text || ',' IN ',' || LOWER(REPLACE(e.sub_indexes,' ','')) || ',')", len(want))
					if !strings.Contains(q, clause) {
						t.Fatalf("sub-index placeholder or membership direction wrong: %s", q)
					}
				}
				want = append(want, "bge-m3", 1024, 20)
				if !reflect.DeepEqual(args, want) || !strings.Contains(q, fmt.Sprintf("LIMIT $%d::bigint", len(want))) {
					t.Fatalf("non-contiguous SQL parameters: args=%v want=%v query=%s", args, want, q)
				}
			})
		}
	}
}
