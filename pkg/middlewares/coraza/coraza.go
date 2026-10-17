package coraza

import (
	"context"
	"net/http"
	"runtime"

	corazahttp "github.com/corazawaf/coraza/v3/http"
	"github.com/traefik/traefik/v3/pkg/middlewares"
	traefikmetrics "github.com/traefik/traefik/v3/pkg/observability/metrics"
)

type wafMiddleware struct {
	name    string
	handler http.Handler
	manager *wafManager
	hash    string
}

// FromPlugin creates a native Coraza middleware from a plugin-style configuration.
func FromPlugin(ctx context.Context, next http.Handler, rawConfig map[string]any, name string, registry traefikmetrics.Registry) (http.Handler, error) {
	config, err := decodeConfiguration(rawConfig)
	if err != nil {
		return nil, err
	}

	return New(ctx, next, config, name, registry)
}

// New creates a native Coraza middleware.
func New(ctx context.Context, next http.Handler, config Configuration, name string, registry traefikmetrics.Registry) (http.Handler, error) {
	logger := middlewares.GetLogger(ctx, name, typeName)

	if err := config.Validate(); err != nil {
		return nil, err
	}

	logger.Debug().Msg("Creating middleware")

	waf, hash, err := defaultWAFManager.getOrCreate(config)
	if err != nil {
		return nil, err
	}

	middleware := &wafMiddleware{
		name:    name,
		handler: corazahttp.WrapHandler(newMetricsWAF(waf, newWAFMetrics(registry, name)), next),
		manager: defaultWAFManager,
		hash:    hash,
	}

	runtime.SetFinalizer(middleware, func(m *wafMiddleware) {
		m.manager.release(m.hash)
	})

	return middleware, nil
}

func (m *wafMiddleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	m.handler.ServeHTTP(rw, req)
}

// GetTracingInformation returns the middleware name and type.
func (m *wafMiddleware) GetTracingInformation() (string, string) {
	return m.name, typeName
}
