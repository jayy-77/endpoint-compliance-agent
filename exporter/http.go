// Package exporter exposes a tiny HTTP surface so the agent can be scraped
// by Prometheus and queried for its latest report. Used by streaming mode.
package exporter

import (
	"encoding/json"
	"net/http"
	"sync"
)

// Server holds the latest report and exposes /report, /healthz, /metrics.
type Server struct {
	mu     sync.RWMutex
	report []byte
	addr   string
}

func New(addr string) *Server {
	return &Server{addr: addr}
}

// SetReport stores the latest snapshot's JSON.
func (s *Server) SetReport(b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.report = append([]byte(nil), b...)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/report", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		if s.report == nil {
			_, _ = w.Write([]byte(`{"status":"no report yet"}`))
			return
		}
		_, _ = w.Write(s.report)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	return mux
}

// ListenAndServe starts the HTTP server. Blocks until the listener errors.
func (s *Server) ListenAndServe() error {
	return http.ListenAndServe(s.addr, s.Handler())
}
