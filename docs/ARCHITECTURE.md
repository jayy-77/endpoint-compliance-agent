# Architecture

## Modes
- **One-shot** (default): collect → analyze → score → report → exit.
- **Streaming** (`--streaming`): loop forever, snapshot every `interval`,
  feed snapshots into the baseline, score each one, expose latest report
  on `/report`, append features to JSONL for offline retraining.

## Layers

```
┌────────────────────────────────────────────────────────────────┐
│                       compliance-agent (Go)                    │
│                                                                │
│   ┌──────────┐    ┌───────────┐    ┌──────────┐    ┌────────┐  │
│   │collector │ ─► │ baseline  │ ─► │  ml/     │ ─► │analyzer│  │
│   │ osquery  │    │  store    │    │ features │    │compliance│ │
│   │ fallback │    │  (JSON)   │    │ (10-dim) │    └────────┘  │
│   └──────────┘    └───────────┘    └────┬─────┘                │
│                                          │                     │
│                                          ▼                     │
│                                  ┌───────────────┐             │
│                                  │ ml.Scorer     │             │
│                                  │ (HTTP / heur) │             │
│                                  └───────┬───────┘             │
│                                          │                     │
│              ┌───────────────────────────┴────────────────┐    │
│              ▼                                             ▼    │
│    ┌──────────────────┐                       ┌─────────────┐  │
│    │  report (JSON)   │                       │  exporter   │  │
│    │  + alerting/Slack│                       │ /report     │  │
│    └──────────────────┘                       └─────────────┘  │
└─────────────────────────────┬──────────────────────────────────┘
                              │ HTTP
                              ▼
                  ┌────────────────────────┐
                  │ ml_service (Python)    │
                  │ FastAPI + IsolationFst │
                  │ /score, /metrics       │
                  └────────────────────────┘
```

## Feature schema (10 features)

Built in `ml/features.go::BuildFeatures` and mirrored in `ml_service/main.py::FEATURE_ORDER`:

| Feature | Meaning |
|---|---|
| `process_count` | Total processes observed in snapshot |
| `unique_processes` | Distinct process names |
| `unknown_process_ratio` | Fraction of process names never seen in baseline |
| `open_port_count` | Listening ports in snapshot |
| `unknown_port_ratio` | Fraction of ports never seen in baseline |
| `user_count` | Local user count |
| `pkg_count` | Installed packages |
| `process_count_zscore` | Z-score vs. rolling user-count series |
| `user_count_zscore` | Z-score vs. rolling user-count series |
| `pkg_count_zscore` | Z-score vs. rolling pkg-count series |

The "unknown_*_ratio" features are the big behavioral signals: a fresh process or an unexpected port is the easiest thing for a host-level UEBA to spot.

## Heuristic / ML symmetry

`ml.HeuristicScore` in Go and `_heuristic` in `ml_service/main.py` are
bit-for-bit equivalent. The service falls back to the heuristic when no
model file is present, so the system never silently returns nonsense
before the model is trained.

## Training loop
1. Streaming mode appends per-snapshot feature dicts to `snapshots.jsonl`.
2. `ml_service/train.py` reads the JSONL, fits an IsolationForest +
   StandardScaler, writes the joblib bundle.
3. Restart `ml-service` to pick up the new model.

## Drift trigger
Same conventions as the sister redpanda repo:
- PSI ≥ 0.2 on any 3 features for >1h → retrain.
- Heuristic-fallback rate > 5% sustained → investigate model server.
