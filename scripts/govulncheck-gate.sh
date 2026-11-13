#!/usr/bin/env bash
# govulncheck as a hard gate, minus an explicit per-ID allowlist [CI-13].
#
# Fails on every vulnerability govulncheck reports as called from our code
# (the same findings `govulncheck ./...` exits 3 on), except the OSV IDs in
# ALLOW. An ID not in ALLOW always fails. An allowlisted ID that stops being
# reported is harmless; the script prints a notice so it can be removed.
#
# Every ALLOW entry needs a note in .github/workflows/ci.yml saying why we are
# not exposed and when the entry comes out.
set -euo pipefail

ALLOW=(
	GO-2026-6872 # [CI-13] echo RateLimiter keyed on RealIP() with no IPExtractor
	GO-2026-6875 # [CI-13] echo Proxy middleware forwards client X-Real-IP
)

out=$(mktemp)
trap 'rm -f "$out"' EXIT

# JSON mode exits 0 when it finds vulnerabilities and non-zero only when the
# scan itself fails, which set -e turns into a failed gate.
govulncheck -format json ./... >"$out"

# No config message means no scan ran; never read empty output as clean.
if ! jq -e -n '[inputs | select(.config)] | length > 0' "$out" >/dev/null; then
	echo "::error::govulncheck produced no scan output"
	exit 1
fi

# Symbol-level findings only: trace[0].function is set when our code reaches
# the vulnerable symbol. Module- and package-level findings (imported but not
# called) do not fail plain `govulncheck ./...` either. tr: jq on Windows
# writes CRLF, and the IDs are compared verbatim below.
found=$(jq -r 'select(.finding.trace[0].function != null) | .finding.osv' "$out" | tr -d '\r' | sort -u)

blocking=()
for id in $found; do
	allowed=false
	for a in "${ALLOW[@]}"; do
		[[ $id == "$a" ]] && allowed=true
	done
	if $allowed; then
		echo "::warning::$id allowlisted by CI-13 in .github/workflows/ci.yml"
	else
		blocking+=("$id")
	fi
done

for a in "${ALLOW[@]}"; do
	if ! grep -qxF "$a" <<<"$found"; then
		echo "::notice::$a is no longer reported; remove it from ALLOW and the CI-13 note"
	fi
done

if ((${#blocking[@]} > 0)); then
	for id in "${blocking[@]}"; do
		summary=$(jq -r --arg id "$id" 'select(.osv.id == $id) | .osv.summary' "$out" | tr -d '\r' | head -n 1)
		echo "::error::$id: $summary (https://pkg.go.dev/vuln/$id)"
	done
	echo "Run 'govulncheck ./...' locally for call traces."
	exit 1
fi

echo "govulncheck: no findings outside the CI-13 allowlist"
