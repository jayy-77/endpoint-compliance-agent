package ml

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHeuristicScore_Range(t *testing.T) {
	low := HeuristicScore(Features{
		"unknown_process_ratio": 0.0,
		"unknown_port_ratio":    0.0,
		"pkg_count_zscore":      0.0,
		"user_count_zscore":     0.0,
	})
	assert.InDelta(t, 0.0, low, 1e-9)

	high := HeuristicScore(Features{
		"unknown_process_ratio": 1.0,
		"unknown_port_ratio":    1.0,
		"pkg_count_zscore":      10.0,
		"user_count_zscore":     10.0,
	})
	assert.InDelta(t, 1.0, high, 1e-9)
}

func TestScorer_HeuristicWhenNoURL(t *testing.T) {
	s := NewScorer("", 0)
	out, model, err := s.Score(context.Background(), Features{"unknown_process_ratio": 1.0})
	require.NoError(t, err)
	assert.Equal(t, "heuristic", model)
	assert.Greater(t, out, 0.0)
}

func TestScorer_HTTPRoundtrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"score": 0.73, "model": "isolation_forest"}`))
	}))
	defer srv.Close()

	s := NewScorer(srv.URL, 0)
	score, model, err := s.Score(context.Background(), Features{})
	require.NoError(t, err)
	assert.InDelta(t, 0.73, score, 1e-9)
	assert.Equal(t, "isolation_forest", model)
}

func TestScorer_HTTPDownReturnsErr(t *testing.T) {
	s := NewScorer("http://127.0.0.1:1", 100_000_000) // bogus, short timeout
	_, _, err := s.Score(context.Background(), Features{})
	require.Error(t, err)
}
