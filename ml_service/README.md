# UEBA ML service

A FastAPI scorer the Go agent calls over HTTP. The Go side computes
features locally (`ml/features.go`), POSTs them to `/score`, and routes
high-scoring snapshots into Slack alerts and the JSON report.

## Train

```bash
# 1. Run the Go agent in streaming mode for a few days to seed snapshots.jsonl
#    (see mode/streaming.go in the parent repo).
# 2. Convert snapshots to feature rows
python3 -m ml_service.train --features snapshots.jsonl --out models/ueba.joblib
```

## Serve

```bash
MODEL_PATH=models/ueba.joblib uvicorn main:app --host 0.0.0.0 --port 8000
```

When no model file is present the service falls back to a heuristic that
matches the Go agent's `ml.HeuristicScore`, so the two halves stay
self-consistent during cold start.
