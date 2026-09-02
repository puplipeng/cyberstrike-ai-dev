package multiagent

import (
	"context"
	"errors"
	"testing"

	"cyberstrike-ai/internal/config"
	"github.com/cloudwego/eino/adk/middlewares/skill"
)

type fixtureSkillBackend struct {
	items map[string]skill.Skill
}

func (b *fixtureSkillBackend) List(context.Context) ([]skill.FrontMatter, error) {
	out := make([]skill.FrontMatter, 0, len(b.items))
	for _, item := range b.items {
		out = append(out, item.FrontMatter)
	}
	return out, nil
}

func (b *fixtureSkillBackend) Get(_ context.Context, name string) (skill.Skill, error) {
	item, ok := b.items[name]
	if !ok {
		return skill.Skill{}, errors.New("missing")
	}
	return item, nil
}

func TestPrepareEinoAgenticSkillsStillCreatesReductionBackendWhenSkillsDisabled(t *testing.T) {
	ma := &config.MultiAgentConfig{
		EinoSkills: config.MultiAgentEinoSkillsConfig{Disable: true},
		EinoMiddleware: config.MultiAgentEinoMiddlewareConfig{
			ReductionEnable: true,
		},
	}
	loc, skillMW, fsTools, skillsRoot, err := prepareEinoAgenticSkills(context.Background(), "", ma, nil)
	if err != nil {
		t.Fatal(err)
	}
	if loc == nil {
		t.Fatal("agentic reduction backend must exist even when Skills are disabled")
	}
	if skillMW != nil || fsTools || skillsRoot != "" {
		t.Fatalf("Agentic Skills unexpectedly enabled: mw=%v fs=%v root=%q", skillMW, fsTools, skillsRoot)
	}
}

func TestReviewGatedSkillBackendOnlyExposesApprovedSkills(t *testing.T) {
	inner := &fixtureSkillBackend{items: map[string]skill.Skill{
		"approved": {FrontMatter: skill.FrontMatter{Name: "approved"}, Content: "allowed"},
		"pending":  {FrontMatter: skill.FrontMatter{Name: "pending"}, Content: "blocked"},
	}}
	backend := &reviewGatedSkillBackend{inner: inner, approved: map[string]struct{}{"approved": {}}}
	items, err := backend.List(context.Background())
	if err != nil || len(items) != 1 || items[0].Name != "approved" {
		t.Fatalf("unexpected approved skill list: %+v %v", items, err)
	}
	if _, err = backend.Get(context.Background(), "approved"); err != nil {
		t.Fatal(err)
	}
	if _, err = backend.Get(context.Background(), "pending"); err == nil {
		t.Fatal("pending skill was loadable")
	}
}
