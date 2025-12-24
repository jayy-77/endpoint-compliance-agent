package exporter

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_ReportEndpoint(t *testing.T) {
	s := New(":0")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	// before any report
	r, err := http.Get(srv.URL + "/report")
	require.NoError(t, err)
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	assert.Contains(t, string(body), "no report yet")

	s.SetReport([]byte(`{"hostname":"x"}`))
	r, err = http.Get(srv.URL + "/report")
	require.NoError(t, err)
	body, _ = io.ReadAll(r.Body)
	r.Body.Close()
	assert.Contains(t, string(body), `"hostname":"x"`)
}

func TestServer_Healthz(t *testing.T) {
	s := New(":0")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	r, err := http.Get(srv.URL + "/healthz")
	require.NoError(t, err)
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	assert.Contains(t, string(body), "ok")
}
