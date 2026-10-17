package coraza

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	traefikmetrics "github.com/traefik/traefik/v3/pkg/observability/metrics"
)

func TestNew_RequiresDirectives(t *testing.T) {
	_, err := New(context.Background(), http.NotFoundHandler(), Configuration{}, "test", traefikmetrics.NewVoidRegistry())
	require.EqualError(t, err, "missing directives values")
}

func TestDecodeConfiguration_StringValues(t *testing.T) {
	config, err := decodeConfiguration(map[string]any{
		"directives": "SecRuleEngine On",
		"crsEnabled": "true",
	})
	require.NoError(t, err)

	assert.Equal(t, []string{"SecRuleEngine On"}, config.Directives)
	assert.True(t, config.CRSEnabled)
}

func TestMiddleware_DenyRequest(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		nextCalled = true
		rw.WriteHeader(http.StatusOK)
	})

	config := Configuration{
		Directives: []string{
			"SecRuleEngine On",
			`SecRule REQUEST_URI "@contains /admin" "id:101,phase:1,deny,status:403,log"`,
		},
	}

	handler, err := New(context.Background(), next, config, "test", traefikmetrics.NewVoidRegistry())
	require.NoError(t, err)

	t.Run("blocked", func(t *testing.T) {
		nextCalled = false
		req := httptest.NewRequest(http.MethodGet, "http://example.com/admin", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.False(t, nextCalled)
	})

	t.Run("allowed", func(t *testing.T) {
		nextCalled = false
		req := httptest.NewRequest(http.MethodGet, "http://example.com/public", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, nextCalled)
	})
}

func TestMiddleware_DenyResponse(t *testing.T) {
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = rw.Write([]byte("this response contains a secret"))
	})

	config := Configuration{
		Directives: []string{
			"SecRuleEngine On",
			"SecRequestBodyAccess On",
			"SecResponseBodyAccess On",
			"SecResponseBodyMimeType text/plain",
			`SecRule RESPONSE_BODY "@contains secret" "id:102,phase:4,deny,status:403,log"`,
		},
	}

	handler, err := New(context.Background(), next, config, "test", traefikmetrics.NewVoidRegistry())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestMiddleware_CRSCompiles(t *testing.T) {
	config := Configuration{
		CRSEnabled: true,
		Directives: []string{
			"Include @coraza.conf-recommended",
			"Include @crs-setup.conf.example",
			"Include @owasp_crs/*.conf",
			"SecRuleEngine On",
		},
	}

	handler, err := New(context.Background(), http.NotFoundHandler(), config, "test", traefikmetrics.NewVoidRegistry())
	require.NoError(t, err)
	require.NotNil(t, handler)
}
