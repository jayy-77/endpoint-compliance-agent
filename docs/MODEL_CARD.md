# Model Card — Endpoint UEBA

## Task
Score whether the current endpoint snapshot is anomalous vs. the host's
own learned baseline. A "0.0" means "looks like a normal day for this
host"; "1.0" means "I have not seen anything like this".

## Inputs
10 features derived from the Go agent's snapshot (see `docs/ARCHITECTURE.md`).
Features are dimensionless ratios or counts; the model is per-host scaled
by `StandardScaler` to keep the score calibration consistent.

## Outputs
`{score, model}` where score ∈ [0, 1] and model is the sklearn class name
(or "heuristic" when no trained model is present).

## Intended use
- Driving SOAR rules on `anomaly == true && violations > 0`
- As a complement to deterministic policy violations from `analyzer/`,
  not a replacement

## Out-of-scope
- Cross-host or population-wide UEBA — this model is per-host
- Container-internal process attribution
- Slow drift attacks that move the baseline; mitigated only partially by
  the rolling-window PSI policy

## Default model
IsolationForest, `n_estimators=200`, `contamination=0.02`. Chosen because:
- No labeled anomalies required
- Robust to heterogeneous feature scales (after StandardScaler)
- Cheap inference (<1ms server-side)

## Training data
Self-supervised on the host's own snapshots collected during a known-good
warmup period (typically 7-14 days in streaming mode). Operators are
responsible for tagging that period as "clean."

## Risks
- Model trained during a compromised period will treat compromise as
  normal. Operators should validate the warmup window with `analyzer/`
  compliance checks before declaring it as training data.
- New legitimate software installs spike the `unknown_process_ratio` for
  ~24h. Threshold tuning or short cool-down windows handle this in practice.
