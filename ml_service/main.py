"""FastAPI service that scores endpoint feature vectors for behavioral anomalies.

Designed to be called by the Go agent's ml.Scorer over HTTP. Loads a joblib
bundle at startup if one is present; otherwise falls back to a heuristic
identical to the Go-side fallback so the two halves stay in agreement.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Dict

import joblib
import numpy as np
from fastapi import FastAPI
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel
from starlette.responses import Response

log = logging.getLogger("ueba")
logging.basicConfig(level=logging.INFO)

MODEL_PATH = os.environ.get("MODEL_PATH", "/models/ueba.joblib")

FEATURE_ORDER = [
    "process_count",
    "unique_processes",
    "unknown_process_ratio",
    "open_port_count",
    "unknown_port_ratio",
    "user_count",
    "pkg_count",
    "process_count_zscore",
    "user_count_zscore",
    "pkg_count_zscore",
]

app = FastAPI(title="endpoint-compliance UEBA", version="0.1.0")

_score_count = Counter("ueba_scored_total", "Records scored")
_score_latency = Histogram("ueba_score_latency_seconds", "Score latency")
_heuristic_fallbacks = Counter("ueba_heuristic_fallbacks_total", "Falls back to heuristic")

_model = None
_scaler = None


class ScoreRequest(BaseModel):
    features: Dict[str, float]


class ScoreResponse(BaseModel):
    score: float
    model: str


def _load() -> None:
    global _model, _scaler
    path = Path(MODEL_PATH)
    if not path.exists():
        log.warning("no model at %s — using heuristic fallback until present", path)
        return
    try:
        bundle = joblib.load(path)
        _model = bundle["model"]
        _scaler = bundle.get("scaler")
        log.info("loaded %s (%s)", path, type(_model).__name__)
    except Exception:
        log.exception("model load failed")


@app.on_event("startup")
def _startup() -> None:
    _load()


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "model_loaded": _model is not None}


@app.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


def _heuristic(feats: Dict[str, float]) -> float:
    s = 0.0
    s += min(feats.get("unknown_process_ratio", 0.0), 1.0) * 0.4
    s += min(feats.get("unknown_port_ratio", 0.0), 1.0) * 0.3
    s += min(abs(feats.get("pkg_count_zscore", 0.0)) / 4.0, 1.0) * 0.15
    s += min(abs(feats.get("user_count_zscore", 0.0)) / 4.0, 1.0) * 0.15
    return min(s, 1.0)


@app.post("/score", response_model=ScoreResponse)
def score(req: ScoreRequest) -> ScoreResponse:
    if _model is None:
        _heuristic_fallbacks.inc()
        return ScoreResponse(score=_heuristic(req.features), model="heuristic")
    vec = np.asarray([[req.features.get(k, 0.0) for k in FEATURE_ORDER]], dtype=float)
    if _scaler is not None:
        vec = _scaler.transform(vec)
    with _score_latency.time():
        raw = -_model.decision_function(vec)[0]
        s = float(np.clip((raw + 0.5) / 1.0, 0.0, 1.0))
    _score_count.inc()
    return ScoreResponse(score=s, model=type(_model).__name__)
