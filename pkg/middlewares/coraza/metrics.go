package coraza

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	corazalib "github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
	gokitmetrics "github.com/go-kit/kit/metrics"
	traefikmetrics "github.com/traefik/traefik/v3/pkg/observability/metrics"
)

type wafMetrics interface {
	record(outcome string, duration time.Duration, interruption *types.Interruption, matchedRules []types.MatchedRule)
}

type registryWAFMetrics struct {
	middleware    string
	requests      gokitmetrics.Counter
	interruptions gokitmetrics.Counter
	duration      traefikmetrics.ScalableHistogram
	ruleMatches   gokitmetrics.Counter
}

func newWAFMetrics(registry traefikmetrics.Registry, middleware string) wafMetrics {
	if registry == nil {
		return nil
	}

	requests := registry.WAFRequestsCounter()
	interruptions := registry.WAFInterruptionsCounter()
	duration := registry.WAFRequestDurationHistogram()
	ruleMatches := registry.WAFRuleMatchesCounter()
	if requests == nil || interruptions == nil || duration == nil || ruleMatches == nil {
		return nil
	}

	return &registryWAFMetrics{
		middleware:    middleware,
		requests:      requests,
		interruptions: interruptions,
		duration:      duration,
		ruleMatches:   ruleMatches,
	}
}

func (m *registryWAFMetrics) record(outcome string, duration time.Duration, interruption *types.Interruption, matchedRules []types.MatchedRule) {
	m.requests.With("middleware", m.middleware, "outcome", outcome).Add(1)
	m.duration.With("middleware", m.middleware, "outcome", outcome).Observe(duration.Seconds())

	if interruption != nil {
		phase := "0"
		for _, matchedRule := range matchedRules {
			rule := matchedRule.Rule()
			if rule != nil && rule.ID() == interruption.RuleID {
				phase = strconv.Itoa(int(rule.Phase()))
				break
			}
		}

		status := interruption.Status
		if status == 0 {
			status = http.StatusForbidden
		}

		m.interruptions.With(
			"middleware", m.middleware,
			"action", interruption.Action,
			"rule_id", strconv.Itoa(interruption.RuleID),
			"phase", phase,
			"status", strconv.Itoa(status),
		).Add(1)
	}

	for _, matchedRule := range matchedRules {
		rule := matchedRule.Rule()
		if rule == nil {
			continue
		}

		m.ruleMatches.With(
			"middleware", m.middleware,
			"rule_id", strconv.Itoa(rule.ID()),
			"severity", rule.Severity().String(),
		).Add(1)
	}
}

type metricsWAF struct {
	waf     corazalib.WAF
	metrics wafMetrics
}

func newMetricsWAF(waf corazalib.WAF, metrics wafMetrics) corazalib.WAF {
	if metrics == nil {
		return waf
	}

	return &metricsWAF{waf: waf, metrics: metrics}
}

func (m *metricsWAF) NewTransaction() types.Transaction {
	return &metricsTransaction{
		Transaction: m.waf.NewTransaction(),
		metrics:     m.metrics,
		start:       time.Now(),
	}
}

func (m *metricsWAF) NewTransactionWithID(id string) types.Transaction {
	return &metricsTransaction{
		Transaction: m.waf.NewTransactionWithID(id),
		metrics:     m.metrics,
		start:       time.Now(),
	}
}

func (m *metricsWAF) NewTransactionWithOptions(opts experimental.Options) types.Transaction {
	waf, ok := m.waf.(experimental.WAFWithOptions)
	if !ok {
		return m.NewTransaction()
	}

	return &metricsTransaction{
		Transaction: waf.NewTransactionWithOptions(opts),
		metrics:     m.metrics,
		start:       time.Now(),
	}
}

type metricsTransaction struct {
	types.Transaction
	metrics wafMetrics
	start   time.Time
	once    sync.Once
}

func (t *metricsTransaction) Close() error {
	t.once.Do(func() {
		interruption := t.Transaction.Interruption()
		matchedRules := t.Transaction.MatchedRules()

		outcome := "allowed"
		switch {
		case interruption != nil:
			outcome = "blocked"
			if interruption.Action == "redirect" {
				outcome = "redirected"
			}
		case len(matchedRules) > 0:
			outcome = "detected"
		}

		t.metrics.record(outcome, time.Since(t.start), interruption, matchedRules)
	})

	return t.Transaction.Close()
}
