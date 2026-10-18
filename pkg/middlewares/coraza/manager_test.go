package coraza

import (
	"sync"
	"testing"
	"time"

	corazalib "github.com/corazawaf/coraza/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWAFManager_ConcurrentCompilation(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})

	manager := &wafManager{
		entries: map[string]*wafEntry{},
		build: func(Configuration) (corazalib.WAF, error) {
			started <- struct{}{}
			<-release
			return nil, nil
		},
	}

	configs := []Configuration{
		{Directives: []string{"SecRuleEngine On", `SecRule REQUEST_URI "@streq /one" "id:101,phase:1,pass"`}},
		{Directives: []string{"SecRuleEngine On", `SecRule REQUEST_URI "@streq /two" "id:102,phase:1,pass"`}},
	}

	errs := make(chan error, len(configs))
	var wg sync.WaitGroup
	for _, config := range configs {
		wg.Add(1)

		go func() {
			defer wg.Done()

			_, _, err := manager.getOrCreate(config)
			errs <- err
		}()
	}

	for range configs {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			close(release)
			t.Fatal("WAF compilation is serialized by the manager lock")
		}
	}

	close(release)
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}

	require.Len(t, manager.entries, 2)
	for _, entry := range manager.entries {
		assert.Equal(t, 1, entry.refs)
	}
}

func TestWAFManager_DeduplicatesConcurrentCompilation(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})

	manager := &wafManager{
		entries: map[string]*wafEntry{},
		build: func(Configuration) (corazalib.WAF, error) {
			started <- struct{}{}
			<-release
			return nil, nil
		},
	}

	config := Configuration{
		Directives: []string{"SecRuleEngine On", `SecRule REQUEST_URI "@streq /one" "id:101,phase:1,pass"`},
	}

	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			_, _, err := manager.getOrCreate(config)
			errs <- err
		}()
	}

	for range 2 {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			close(release)
			t.Fatal("WAF compilation is serialized by the manager lock")
		}
	}

	close(release)
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}

	require.Len(t, manager.entries, 1)
	for _, entry := range manager.entries {
		assert.Equal(t, 2, entry.refs)
	}
}
