package coraza

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/corazawaf/coraza-coreruleset/v4"
	corazalib "github.com/corazawaf/coraza/v3"
)

// wafCleanupDelay is the delay before an unused, compiled WAF is removed from
// the in-memory pool. It gives Traefik time to rebuild middleware chains after
// a configuration change without recompiling the same rule set immediately.
const wafCleanupDelay = 10 * time.Second

type wafEntry struct {
	waf   corazalib.WAF
	refs  int
	timer *time.Timer
}

type wafManager struct {
	mu      sync.Mutex
	entries map[string]*wafEntry
}

var defaultWAFManager = &wafManager{entries: map[string]*wafEntry{}}

// getOrCreate returns a compiled WAF for the configuration, reusing an existing
// instance when the configuration hash matches.
func (m *wafManager) getOrCreate(config Configuration) (corazalib.WAF, string, error) {
	hash, err := hashConfig(config)
	if err != nil {
		return nil, "", err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if entry, ok := m.entries[hash]; ok {
		entry.refs++
		if entry.timer != nil {
			entry.timer.Stop()
			entry.timer = nil
		}

		return entry.waf, hash, nil
	}

	waf, err := buildWAF(config)
	if err != nil {
		return nil, "", fmt.Errorf("creating WAF: %w", err)
	}

	m.entries[hash] = &wafEntry{waf: waf, refs: 1}

	return waf, hash, nil
}

// release decrements the reference count of a WAF and schedules its cleanup
// when it is no longer used.
func (m *wafManager) release(hash string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.entries[hash]
	if !ok || entry.refs <= 0 {
		return
	}

	entry.refs--
	if entry.refs > 0 {
		return
	}

	if entry.timer != nil {
		entry.timer.Stop()
	}

	entry.timer = time.AfterFunc(wafCleanupDelay, func() {
		m.mu.Lock()
		defer m.mu.Unlock()

		current, ok := m.entries[hash]
		if !ok || current != entry || current.refs > 0 {
			return
		}

		delete(m.entries, hash)

		if closer, ok := current.waf.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	})
}

func buildWAF(config Configuration) (corazalib.WAF, error) {
	wafConfig := corazalib.NewWAFConfig().WithDirectives(strings.Join(config.Directives, "\n"))

	if config.CRSEnabled {
		wafConfig = wafConfig.WithRootFS(coreruleset.FS)
	}

	return corazalib.NewWAF(wafConfig)
}

func hashConfig(config Configuration) (string, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("hashing config: %w", err)
	}

	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:]), nil
}
