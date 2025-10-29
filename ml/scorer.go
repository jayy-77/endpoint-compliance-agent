package ml

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"
)

// ErrServerDown is returned when the ML service is unreachable; callers
// should treat this as "do not score, fall back to pure compliance rules".
var ErrServerDown = errors.New("ml service unreachable")

// Scorer either calls a remote ML service or returns a heuristic z-score
// when no service is configured. This mirrors the redpanda detector's
// scorer pattern: heuristic is the safe default; HTTP is the production
// upgrade.
type Scorer struct {
	url     string
	client  *http.Client
	timeout time.Duration
}

func NewScorer(url string, timeout time.Duration) *Scorer {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &Scorer{
		url:     url,
		timeout: timeout,
		client:  &http.Client{Timeout: timeout},
	}
}

// HeuristicScore is the fallback when no ML service is configured —
// a combination of unknown-process ratio and z-score deviations.
func HeuristicScore(f Features) float64 {
	score := 0.0
	score += math.Min(f["unknown_process_ratio"], 1.0) * 0.4
	score += math.Min(f["unknown_port_ratio"], 1.0) * 0.3
	score += math.Min(math.Abs(f["pkg_count_zscore"])/4.0, 1.0) * 0.15
	score += math.Min(math.Abs(f["user_count_zscore"])/4.0, 1.0) * 0.15
	if score > 1.0 {
		score = 1.0
	}
	return score
}

type scoreReq struct {
	Features Features `json:"features"`
}
type scoreResp struct {
	Score float64 `json:"score"`
	Model string  `json:"model"`
}

// Score calls the ML service. If the service is not configured (empty URL),
// the heuristic baseline is returned instead.
func (s *Scorer) Score(ctx context.Context, f Features) (float64, string, error) {
	if s == nil || s.url == "" {
		return HeuristicScore(f), "heuristic", nil
	}
	body, err := json.Marshal(scoreReq{Features: f})
	if err != nil {
		return 0, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("%w: %v", ErrServerDown, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return 0, "", fmt.Errorf("ml service %d: %s", resp.StatusCode, string(b))
	}
	var out scoreResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, "", err
	}
	return out.Score, out.Model, nil
}
