package coraza

import (
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3/types"
	gokitmetrics "github.com/go-kit/kit/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	traefikmetrics "github.com/traefik/traefik/v3/pkg/observability/metrics"
)

func TestRegistryWAFMetrics_Record(t *testing.T) {
	requests := &recordingCounter{}
	interruptions := &recordingCounter{}
	ruleMatches := &recordingCounter{}
	duration := &recordingHistogram{}

	metrics := &registryWAFMetrics{
		middleware:    "waf",
		requests:      requests,
		interruptions: interruptions,
		duration:      duration,
		ruleMatches:   ruleMatches,
	}

	matchedRules := []types.MatchedRule{
		fakeMatchedRule{rule: fakeRuleMetadata{}},
	}

	metrics.record("blocked", 10*time.Millisecond, &types.Interruption{
		Action: "deny",
		RuleID: 101,
		Status: 403,
	}, matchedRules)

	assert.Equal(t, float64(1), requests.total)
	assert.Equal(t, []string{"middleware", "waf", "outcome", "blocked"}, requests.lastLabels)
	assert.Equal(t, float64(1), interruptions.total)
	assert.Equal(t, []string{
		"middleware", "waf",
		"action", "deny",
		"rule_id", "101",
		"phase", "1",
		"status", "403",
	}, interruptions.lastLabels)
	assert.Equal(t, float64(1), ruleMatches.total)
	assert.Equal(t, []string{"middleware", "waf", "rule_id", "101", "severity", "critical"}, ruleMatches.lastLabels)
	require.Len(t, duration.values, 1)
	assert.InDelta(t, 0.01, duration.values[0], 1e-9)
	assert.Equal(t, []string{"middleware", "waf", "outcome", "blocked"}, duration.lastLabels)

	metrics.record("allowed", 5*time.Millisecond, nil, nil)

	assert.Equal(t, float64(2), requests.total)
	assert.Equal(t, []string{"middleware", "waf", "outcome", "allowed"}, requests.lastLabels)
	assert.Equal(t, float64(1), interruptions.total)
	assert.Len(t, duration.values, 2)
}

type recordingCounter struct {
	total      float64
	lastLabels []string
}

func (c *recordingCounter) With(labelValues ...string) gokitmetrics.Counter {
	c.lastLabels = labelValues
	return c
}

func (c *recordingCounter) Add(delta float64) {
	c.total += delta
}

type recordingHistogram struct {
	values     []float64
	lastLabels []string
}

func (h *recordingHistogram) With(labelValues ...string) traefikmetrics.ScalableHistogram {
	h.lastLabels = labelValues
	return h
}

func (h *recordingHistogram) Observe(value float64) {
	h.values = append(h.values, value)
}

func (h *recordingHistogram) ObserveFromStart(time.Time) {}

type fakeRuleMetadata struct {
	types.RuleMetadata
}

func (f fakeRuleMetadata) ID() int                      { return 101 }
func (f fakeRuleMetadata) Severity() types.RuleSeverity { return types.RuleSeverityCritical }
func (f fakeRuleMetadata) Phase() types.RulePhase       { return types.PhaseRequestHeaders }

type fakeMatchedRule struct {
	types.MatchedRule
	rule types.RuleMetadata
}

func (f fakeMatchedRule) Rule() types.RuleMetadata { return f.rule }
