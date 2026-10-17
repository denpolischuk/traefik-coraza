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
	build   func(Configuration) (corazalib.WAF, error)
}

var defaultWAFManager = &wafManager{
	entries: map[string]*wafEntry{},
	build:   buildWAF,
}

// getOrCreate returns a compiled WAF for the configuration, reusing an existing
// instance when the configuration hash matches.
//
// Compilation is intentionally performed outside the manager lock. Rule set
// compilation can take hundreds of milliseconds for the OWASP CRS, and holding
// the lock during compilation would serialize unrelated configuration reloads.
func (m *wafManager) getOrCreate(config Configuration) (corazalib.WAF, string, error) {
	hash, err := hashConfig(config)
	if err != nil {
		return nil, "", err
	}

	m.mu.Lock()
	if entry, ok := m.entries[hash]; ok {
		m.acquire(entry)
		m.mu.Unlock()

		return entry.waf, hash, nil
	}
	m.mu.Unlock()

	// Compile without holding the lock so different configurations can be
	// compiled concurrently.
	build := m.build
	if build == nil {
		build = buildWAF
	}

	waf, err := build(config)
	if err != nil {
		return nil, "", fmt.Errorf("creating WAF: %w", err)
	}

	m.mu.Lock()
	// Another goroutine may have compiled and inserted the same configuration
	// while this one was compiling. Preserve the deduplication guarantee by
	// reusing the inserted entry and discarding the duplicate.
	if entry, ok := m.entries[hash]; ok {
		m.acquire(entry)
		m.mu.Unlock()

		closeWAF(waf)

		return entry.waf, hash, nil
	}

	m.entries[hash] = &wafEntry{waf: waf, refs: 1}
	m.mu.Unlock()

	return waf, hash, nil
}

// acquire increments the reference count of an entry and cancels a pending
// cleanup. The caller must hold the manager lock.
func (m *wafManager) acquire(entry *wafEntry) {
	entry.refs++
	if entry.timer != nil {
		entry.timer.Stop()
		entry.timer = nil
	}
}

// release decrements the reference count of a WAF and schedules its cleanup
// when it is no longer used.
func (m *wafManager) release(hash string) {
	m.mu.Lock()

	entry, ok := m.entries[hash]
	if !ok || entry.refs <= 0 {
		m.mu.Unlock()
		return
	}

	entry.refs--
	if entry.refs > 0 {
		m.mu.Unlock()
		return
	}

	if entry.timer != nil {
		entry.timer.Stop()
	}

	entry.timer = time.AfterFunc(wafCleanupDelay, func() {
		m.mu.Lock()

		current, ok := m.entries[hash]
		if !ok || current != entry || current.refs > 0 {
			m.mu.Unlock()
			return
		}

		delete(m.entries, hash)
		m.mu.Unlock()

		closeWAF(current.waf)
	})

	m.mu.Unlock()
}

func closeWAF(waf corazalib.WAF) {
	if closer, ok := waf.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
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
