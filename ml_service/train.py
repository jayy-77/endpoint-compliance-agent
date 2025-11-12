"""Train a UEBA anomaly detector from snapshots collected by the Go agent.

Input: a JSONL file where each line is a feature dict (one record per snapshot).
Output: joblib bundle that ml_service/main.py can load.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from main import FEATURE_ORDER


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", required=True, help="JSONL of feature dicts")
    ap.add_argument("--out", default="models/ueba.joblib")
    ap.add_argument("--contamination", type=float, default=0.02)
    args = ap.parse_args()

    rows: list[list[float]] = []
    with Path(args.features).open() as f:
        for line in f:
            d = json.loads(line)
            rows.append([d.get(k, 0.0) for k in FEATURE_ORDER])
    X = np.asarray(rows, dtype=float)
    print(f"loaded {len(X)} snapshots")

    scaler = StandardScaler().fit(X)
    model = IsolationForest(
        n_estimators=200, contamination=args.contamination, random_state=42, n_jobs=-1
    )
    model.fit(scaler.transform(X))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "scaler": scaler, "feature_order": FEATURE_ORDER}, out)
    print(f"saved {out}")


if __name__ == "__main__":
    main()
