#!/bin/bash
# Core performance harness.
#
#   scripts/perf/run.sh                 # all scenarios, median of N=5 runs
#   N=3 scripts/perf/run.sh basic plan  # selected scenarios
#   scripts/perf/run.sh golden          # check scan output is byte-identical to golden.json
#   node scripts/perf/ui-bench.mjs 3000  # Web UI scan loop in headless Chromium (needs Playwright)
#
# Bundles packages/core/src with esbuild (the way the CLI ships it), then runs each
# scenario in a fresh Node process so import cost and GC counts are per-run.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/../.."
mkdir -p "$DIR/.out"
"$ROOT/node_modules/.bin/esbuild" "$ROOT/packages/core/src/index.ts" --bundle --platform=node --format=esm \
	--outfile="$DIR/.out/core.mjs" --log-level=error

if [ "$1" = golden ]; then
	node "$DIR/golden.mjs" 2>/dev/null | diff - "$DIR/golden.json" && echo "golden: OK"
	exit
fi

N=${N:-5}
for s in ${@:-import basic encpaged heavy3pages padding bigbody verdict signature plan}; do
	for i in $(seq "$N"); do node --expose-gc "$DIR/bench.mjs" "$s" 2>/dev/null; done | node -e '
		const rows = require("fs").readFileSync(0, "utf8").trim().split("\n").map(JSON.parse);
		const med = (k) => { const v = rows.map((r) => r[k]).sort((a, b) => a - b); return v[v.length >> 1]; };
		const o = { scenario: rows[0].scenario };
		for (const k of Object.keys(rows[0])) if (typeof rows[0][k] === "number") o[k] = med(k);
		console.log(JSON.stringify(o));'
done
