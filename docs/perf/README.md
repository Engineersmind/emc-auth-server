# docs/perf/ — perf run output (issue #218)

One directory per run: `docs/perf/<YYYY-MM-DD>/<scenario>-<git-sha>-<HHMMSS>Z/`

- `summary.json` — the full k6 `--summary-export` payload (all metrics,
  per-flow latency percentiles, threshold results)
- `meta.json` — run metadata: commit sha, scenario, targets file used, target
  host, placeholder flags, start time
- `report.html` — standalone HTML report (metric table with per-threshold
  pass/fail, breached-threshold banner, placeholder banner)

`perf/scripts/results-dir.js` prints the path for a given scenario; the caller
creates it (k6 will not), then sets it as `RESULTS_DIR` for `k6 run`.

Dated run dirs are gitignored — CI uploads them as the `perf-smoke-results`
artifact instead. See `perf/README.md` for the run loop.
